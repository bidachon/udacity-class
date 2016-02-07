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
import cgi
import re
import os
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

class Blog(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	#last_modified = db.DateProperty(auto_now = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainHandler(Handler):

	def get(self):
		blogs = db.GqlQuery("select * from Blog")
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
		self.render('viewpost.html',title=title, content=content, created=created)




app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/blog',MainHandler),
	('/blog/newpost',NewPostHandler),
	('/blog/([0-9]+)',ViewPostHandler)], debug=True)