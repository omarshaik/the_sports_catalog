from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
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
        print "Token's client ID does not match app's."
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

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exists locally
    user_id = get_user_id(login_session['email'])
    if not user_id:
    	user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions
def create_user(login_session):
	new_user = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
	session.add(new_user)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id

def get_user_info(user_id):
	user = session.query(User).filter_by(id=user_id).one()
	return user

def get_user_id(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
 	print 'Access Token is None'
    	response = make_response(json.dumps('Current user not connected.'), 401)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
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
    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response

# Show the entire catalog
@app.route('/')
@app.route('/catalog/')
def show_catalog():
	categories = session.query(Category).all()
	if 'username' not in login_session:
		return render_template('public_catalog.html', categories=categories)
	else:
		return render_template('catalog.html', categories=categories)

# Show a category's items
@app.route('/catalog/category/<int:category_id>/')
@app.route('/catalog/category/<int:category_id>/items/')
def show_category(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = get_user_info(category.user_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
    	return render_template('public_category.html', items=items, category=category)
    else:
    	return render_template('category.html', items=items, category=category)

# Show a particular item
@app.route('/catalog/category/<int:category_id>/items/<int:item_id>/')
def show_item(category_id, item_id):
	item = session.query(Item).filter_by(id=item_id).one()
	creator = get_user_info(item.user_id)
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('public_item.html', item=item, category_id=category_id)
	else:
		return render_template('item.html', item=item, category_id=category_id)

# Create a new category
@app.route('/catalog/category/new/', methods=['GET', 'POST'])
def new_category():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		new_category = Category(name=request.form['name'], user_id=login_session['user_id'])
		session.add(new_category)
		session.commit()
		return redirect(url_for('show_catalog'))
	else:
		return render_template('new_category.html')

# Edit a category
@app.route('/catalog/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit_category(category_id):
	if 'username' not in login_session:
		return redirect('/login')
	edited_category = session.query(Category).filter_by(id=category_id).one()
	if edited_category.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to edit this category.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		if request.form['name']:
			edited_category.name = request.form['name']
			return redirect(url_for('show_catalog'))
	else:
		return render_template('edit_category.html', category=edited_category)

# Delete a category
@app.route('/catalog/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
	if 'username' not in login_session:
		return redirect('/login')
	category_to_delete = session.query(Category).filter_by(id=category_id).one()
	if category_to_delete.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to delete this category.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		session.delete(category_to_delete)
		session.commit()
		return redirect(url_for('show_catalog'))
	else:
		return render_template('delete_category.html', category=category_to_delete)

# Create a new item
@app.route('/catalog/category/<int:category_id>/items/new', methods=['GET', 'POST'])
def new_item(category_id):
	if 'username' not in login_session:
		return redirect('/login')
	category = session.query(Category).filter_by(id=category_id).one()
	if login_session['user_id'] != category.user_id:
		return "<script>function myFunction() {alert('You are not authorized to add items to this category. Please create your own category in order to add items.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		new_item = Item(name=request.form['name'], description=request.form['description'], category=category, user_id=category.user_id)
		session.add(new_item)
		session.commit()
		return redirect(url_for('show_category', category_id=category_id))
	else:
		return render_template('new_item.html', category_id=category_id)

# Edit an item
@app.route('/catalog/category/<int:category_id>/items/<int:item_id>/edit/', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
	if 'username' not in login_session:
		return redirect('/login')
	edited_item = session.query(Item).filter_by(id=item_id).one()
	category = session.query(Category).filter_by(id=category_id).one()
	if login_session['user_id'] != category.user_id:
		return "<script>function myFunction() {alert('You are not authorized to edit items in this category. Please create your own category in order to edit items.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		if request.form['name']:
			edited_item.name = request.form['name']
		if request.form['description']:
			edited_item.description = request.form['description']
		session.add(edited_item)
		session.commit()
		return redirect(url_for('show_category', category_id=category_id))
	else:
		return render_template('edit_item.html', category_id=category_id, item_id=item_id, item=edited_item)

# Delete an item
@app.route('/catalog/category/<int:category_id>/items/<int:item_id>/delete/', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
	if 'username' not in login_session:
		return redirect('/login')
	item_to_delete = session.query(Item).filter_by(id=item_id).one()
	category = session.query(Category).filter_by(id=category_id).one()
	if login_session['user_id'] != category.user_id:
		return "<script>function myFunction() {alert('You are not authorized to delete items in this category. Please create your own category in order to delete items.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		session.delete(item_to_delete)
		session.commit()
		return redirect(url_for('show_category', category_id=category_id))
	else:
		return render_template('delete_item.html', category_id=category_id, item_id=item_id, item=item_to_delete)

# JSON endpoints
@app.route('/catalog/JSON')
def catalog_JSON():
	categories = session.query(Category).all()
	return jsonify(categories=[c.serialize for c in categories])

@app.route('/catalog/category/<int:category_id>/items/JSON')
def items_JSON(category_id):
	category = session.query(Category).filter_by(id=category_id).one()
	items = session.query(Item).filter_by(category_id=category_id).all()
	return jsonify(items=[i.serialize for i in items])

@app.route('/catalog/category/<int:category_id>/items/<int:item_id>/JSON')
def item_JSON(category_id, item_id):
	item = session.query(Item).filter_by(id=item_id).one()
	return jsonify(item=item.serialize)

if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=8000)