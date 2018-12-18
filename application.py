"""application.py"""

import random
import string
import json
import flask
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from flask import session as login_session
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
from database_setup import Base, User, Category, Item

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

engine = create_engine('sqlite:///categorizeditems.db')
Base = declarative_base()
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# LOGIN
@app.route('/login')
def showLogin():
    """Displays the login page"""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# CONNECT
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Get token from Google OAuth"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']
    output += '!</h3>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 50px; height: 50px;border-radius: 150px;""'
    output += '"-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route("/gdisconnect")
def gdisconnect():
    """Disconnect from Google OAauth"""
        # only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
        # Execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Categories List
@app.route('/')
@app.route('/categories/')
def showCategories():
    """Display all categories"""
    session = DBSession()
    categories = session.query(Category).order_by(Category.name)
    if 'username' in login_session:
        return render_template('categories.html', categories=categories)
    else:
        return render_template('categoriespublic.html', categories=categories)

# Categories JSON
@app.route('/categories/JSON/')
def showCategoriesJSON():
    """Returns JSON for all categories"""
    session = DBSession()
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])

# Category items JSON
@app.route('/categories/<int:category_id>/items/JSON/')
def showCategoryItemsJSON(category_id):
    """Shows JSON for all items in a category"""
    session = DBSession()
    items = session.query(Item).filter_by(category_id=category_id)
    return jsonify(Items=[i.serialize for i in items])

# item JSON
@app.route('/categories/<int:category_id>/items/<int:item_id>/JSON/')
def showItemJSON(category_id, item_id):
    """Shows JSON for a single item"""
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)

# New category
@app.route('/categories/new/', methods=['GET', 'POST'])
def createCategory():
    """Create a new category"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if request.method == 'POST':
        session = DBSession()
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newcategory.html')

# Edit Category
@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """Edit an existing category"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    session = DBSession()
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this category.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('editcategory.html', category=editedCategory)

# Delete category
@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """Delete an existing category"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    session = DBSession()
    deletedCategory = session.query(Category).filter_by(id=category_id).one()
    if deletedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this category.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(deletedCategory)
        deletedItems = session.query(Item).filter_by(
            category_id=category_id).all()
        for i in deletedItems:
            session.delete(i)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deletecategory.html', category=deletedCategory)

# Category items list
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showCategoryItems(category_id):
    """Show all items in a particular category"""
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(
        category_id=category.id).order_by(asc(Item.name))
    # or creator.id != login_session['user_id']:
    if 'username' in login_session:
        return render_template('items.html', category=category, items=items)
    else:
        return render_template('itemspublic.html', category=category, items=items, creator=creator)

# New Item
@app.route('/categories/<int:category_id>/items/new', methods=['GET', 'POST'])
def createItem(category_id):
    """Create a new item"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if request.method == 'POST':
        session = DBSession()
        item = Item(name=request.form['name'],
                    description=request.form['description'],
                    category_id=category_id,
                    user_id=login_session['user_id'])
        session.add(item)
        session.commit()
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('newitem.html', category_id=category_id)

# Edit Item


@app.route('/categories/<int:category_id>/items/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    """Edit an existing item"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    session = DBSession()
    editedItem = session.query(Item).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this item.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        editedItem.name = request.form['name']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('edititem.html', category_id=category_id, item=editedItem)

# Delete Item


@app.route('/categories/<int:category_id>/items/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    """Delete an existing item"""
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    session = DBSession()
    deletedItem = session.query(Item).filter_by(id=item_id).one()
    if deletedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this item.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=deletedItem)


def createUser(login_session):
    """Create a new user"""
    session = DBSession()
    newUser = User(name=login_session['username'],
                   email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Get user info from an ID"""
    try:
        session = DBSession()
        return session.query(User).filter_by(id=user_id).one()
    except:
        return None

#get user id from email
def getUserID(email):
    """Get user ID from an e-mail address"""
    try:
        session = DBSession()
        return session.query(User).filter_by(email=email).one().id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
    
