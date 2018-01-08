from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, Catalog, catalogItem, User
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
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Login via Facebook OAuth"""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data

    # Exchange client token for long-lived server-side token
    fb_client_secrets_file = ('fb_client_secrets.json')
    print "fb_client_secrets_file ==== " + fb_client_secrets_file
    app_id = json.loads(
        open(fb_client_secrets_file, 'r').read())['web']['app_id']
    app_secret = json.loads(
        open(fb_client_secrets_file, 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.8/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API.
    url = 'https://graph.facebook.com/v2.9/me?%s&fields=name,id,email' % token
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to proplerly
    # logout, let's strip out the information before the equals sign in
    # our token.
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Check if the user exists in the database. If not create a new user.
    user_id = login_session['email']
    if user_id is None:
        user_id = create_user()
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/fbdisconnect')
@app.route('/fbdisconnect/')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


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
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    try:
        userExists = session.query(User).filter_by(email=login_session['email']).one()
    except:
        newUser = User(name=login_session['username'], email=login_session['email'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(email=login_session['email']).one()
        return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(email=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Restaurant Information
@app.route('/catalog/<int:catalog_id>/item/JSON')
def catalogMenuJSON(catalog_id):
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(catalogItem).filter_by(
        catalog_id=catalog_id).all()
    return jsonify(catalogItem=[i.serialize for i in items])


@app.route('/catalog/<int:catalog_id>/item/<int:cat_id>/JSON')
def itemJSON(catalog_id, cat_id):
    catalog_Item = session.query(catalogItem).filter_by(id=cat_id).one()
    return jsonify(catalog_Item=catalog_Item.serialize)


@app.route('/catalog/JSON')
def catalogsJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs=[r.serialize for r in catalogs])


# Show all Catalogs
@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    items = session.query(catalogItem).order_by(desc(catalogItem.id))
    if 'username' not in login_session:
        return render_template('publiccatalog.html', catalogs=catalogs, items=items)
    else:
        return render_template('catalogs.html', catalogs=catalogs, items=items)


# Create a new Catalog
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCatalog():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if 'provider' in login_session:
            if login_session['provider'] == 'google':
                try:
                    userExists = session.query(User).filter_by(email=login_session['email']).one()
                except:
                    createUser(login_session)
                    
                newCatalog = Catalog(
                    name=request.form['name'], user_id=login_session['email'])
                session.add(newCatalog)
                flash('New Catalog %s Successfully Created' % newCatalog.name)
                session.commit()
                return redirect(url_for('showCatalogs'))
            elif login_session['provider'] == 'facebook':
                try:
                    userExists = session.query(User).filter_by(email=login_session['email']).one()
                except:
                    createUser(login_session)

                newCatalog = Catalog(
                    name=request.form['name'], user_id=login_session['email'])
                session.add(newCatalog)
                flash('New Catalog %s Successfully Created' % newCatalog.name)
                session.commit()
                return redirect(url_for('showCatalogs'))
    else:
        return render_template('newcatalog.html')


# Edit a restauran
@app.route('/catalog/<catalog_name>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_name):
    editedCatalog = session.query(
        Catalog).filter_by(name=catalog_name).one()

    previousName = editedCatalog.name
    if 'username' not in login_session:
        return redirect('/login')
    if editedCatalog.user_id != login_session['email']:
        return "<script>function myFunction() {alert('You are not authorized to edit this Catalog. Please create your own Catalog in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedCatalog.name = request.form['name']
        session.add(editedCatalog)
        session.commit()
        flash('Catalog Successfully Edited %s' % editedCatalog.name)

        items = session.query(catalogItem).filter_by(
            category=previousName).all()
        for item in items:
            item.category = request.form['name']
            session.add(item)
            session.commit()
                
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('editcatalog.html', catalog=editedCatalog)


# Delete a restaurant
@app.route('/catalog/<catalog_name>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalog_name):
    catalogToDelete = session.query(
        Catalog).filter_by(name=catalog_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if catalogToDelete.user_id != login_session['email']:
        return "<script>function myFunction() {alert('You are not authorized to delete this catalog. Please create your own catalog in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(catalogToDelete)
        flash('%s Successfully Deleted' % catalogToDelete.name)
        session.commit()

        items = session.query(catalogItem).filter_by(
            category=catalog_name).all()
        for item in items:
            session.delete(item)
            session.commit()
            
        return redirect(url_for('showCatalogs', catalog_name=catalog_name))
    else:
        return render_template('deletecatalog.html', catalog=catalogToDelete)

# Show a restaurant menu


@app.route('/catalog/<catalog_name>/')
@app.route('/catalog/<catalog_name>/item/')
def showItems(catalog_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    catalog_id = catalog.id
    try:
        creator = getUserInfo(catalog.user_id)
        items = session.query(catalogItem).filter_by(
            catalog_id=catalog_id).all()
        if 'username' not in login_session:
            return render_template('publicitems.html', items=items, catalog=catalog, creator=creator)
        else:
            return render_template('item.html', items=items, catalog=catalog, creator=creator)
    except NoResultFound:
        if 'username' not in login_session:
            return render_template('publicitems.html', items=items, creator=catalog.user_id)
        else:
            return render_template('item.html', items=items, creator=catalog.user_id)

def getCatalogid(category_name):
    catalog = session.query(Catalog).filter_by(name=category_name).one()
    return catalog.id


# Create a new menu item
@app.route('/catalog/<catalog_name>/item/new/', methods=['GET', 'POST'])
def newItem(catalog_name):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()

    allcatalogs = session.query(Catalog).order_by(asc(Catalog.name))
    if login_session['email'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this catalog. Please create your own catalog in order to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = catalogItem(name=request.form['name'], description=request.form['description'],
                              category=request.form['category'], catalog_id=getCatalogid(request.form['category']), user_id=catalog.user_id)
        session.add(newItem)
        session.commit()
        flash('New %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showItems', catalog_name=catalog_name))
    else:
        return render_template('newitem.html', catalog_name=catalog_name, allcatalogs=allcatalogs)

@app.route('/catalog/<catalog_name>/item/<item_name>')
def itemDetail(catalog_name, item_name):
    item = session.query(catalogItem).filter_by(name=item_name).one()
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    try:
        if 'username' not in login_session:
            return render_template('publicitemdetail.html', item=item, catalog=catalog)
        else:
            return render_template('itemdetail.html', item=item, catalog=catalog)
    except NoResultFound:
        if 'username' not in login_session:
            return render_template('publicitemdetail.html', item=item)
        else:
            return render_template('itemdetail.html', item=item)

# Edit a menu item
@app.route('/catalog/<catalog_name>/item/<item_name>/edit', methods=['GET', 'POST'])
def editItem(catalog_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(catalogItem).filter_by(name=item_name).one()
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    if login_session['email'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this catalog. Please create your own catalog in order to edit items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItems', catalog_name=catalog_name))
    else:
        return render_template('edititem.html', catalog_name=catalog_name, item_name=item_name, item=editedItem)


# Delete a menu item
@app.route('/catalog/<catalog_name>/item/<item_name>/delete', methods=['GET', 'POST'])
def deleteItem(catalog_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    itemToDelete = session.query(catalogItem).filter_by(name=item_name).one()
    if login_session['email'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this catalog. Please create your own catalog in order to edit items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems', catalog_name=catalog_name))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        print login_session['provider']
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['username']
            del login_session['email']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalogs'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalogs'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
