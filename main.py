#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Form page to list entries /blog
# Form to submit new entries /blog/newpost title, date, blog error if title or body empty
# Permalink page for entries /blog/XXXXXX with top link to /blog page

import webapp2
import string
import random
from string import letters
import cgi
import re
import os
import hashlib
import hmac
import jinja2
import json

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

secret = 'prout'

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def make_secure_cookie(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_cookie(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_cookie(val):
		return val

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Blog(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	#last_modified = db.DateProperty(auto_now = True)

	def as_json(self):
		time_format = '%c'
		d = {'subject':self.title,
		'content':self.content,
		'created':self.created.strftime(time_format)}
		return d

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render_json(self,d):
		json_text = json.dumps(d)
		self.response.headers['content-type'] = 'application/json; charset=UTF-8'
		self.write(json_text)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_cookie(val)
		self.response.headers.add_header(
		'Set-Cookie',
		'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_cookie(cookie_val)

class MainHandler(Handler):

	def get(self):
		blogs = db.GqlQuery("select * from Blog")
		if self.request.url.endswith('.json'):
			self.render_json([b.as_json() for b in blogs])
		else:
			self.render('list.html', blogs = blogs)

class NewPostHandler(Handler):

	def get(self):
		self.render('newpost.html')

	def post(self):
		title = self.request.get('subject')
		content = self.request.get('content')
		if (title and content):
			p = Blog(title = title, content = content)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "Both title and content should be valid"
			self.render('newpost.html',title=title,content=content,error=error)


class ViewPostHandler(Handler):
	def get(self, blog_id):
		key = db.Key.from_path('Blog', int(blog_id))
		blog = db.get(key)
		if not blog:
			self.error(404)
			return
		title = blog.title
		content = blog.content
		created = blog.created
		if self.request.url.endswith('.json'):
			self.render_json(blog.as_json())
		else:
			self.render('viewpost.html',title=title, content=content, created=created)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class WelcomeHandler(Handler):
	def get(self):
		uid = self.read_secure_cookie('user_id')
		if uid:
			user = User.by_id(int(uid))
		if not uid or not user:
			self.redirect('/blog/signup')
		else:
			username = user.name
			self.write("Hello %s" %username)

class LoginHandler(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.set_secure_cookie('user_id',str(u.key().id()))
			self.redirect('/blog/welcome')
		else:
			msg = 'Invalid login'
			self.render('login.html', error = msg)

class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
		self.redirect('/blog/signup')


class SignUpHandler(Handler):
	def get(self):
		self.render('signup.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		error_username = ''
		error_password = ''
		error_verify = ''
		error_email = ''
		valid = True

		if not valid_username(username):
			error_username = "Invalid username"
			valid = False

		u = User.by_name(username)
		if u:
			error_username = "That user already exists."
			valid = False

		if not valid_password(password):
			error_password = "Invalid password"
			valid = False

		if not password == verify:
			error_verify = "Passwords don't match"
			valid = False 

		if not valid_email(email):
			error_email = "Invalid email"
			valid = False

		if not valid:
			self.render('signup.html', username = username,
				password = password,
				verify = verify,
				email = email,
				error_username = error_username,
				error_password = error_password,
				error_verify = error_verify,
				error_email = error_email)
		else:
			u = User.register(username, password, email)
			u.put()
			self.set_secure_cookie('user_id',str(u.key().id()))
			self.redirect('/blog/welcome')

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/blog',MainHandler),
	('/blog?/(?:\.json)?', MainHandler),
	('/blog/newpost',NewPostHandler),
	('/blog/([0-9]+)/?(?:\.json)?',ViewPostHandler),
	('/blog/signup',SignUpHandler),
	('/blog/login',LoginHandler),
	('/blog/logout',LogoutHandler),
	('/blog/welcome',WelcomeHandler)], debug=True)