import os
import webapp2
import jinja2
import re
import random
import hashlib
import hmac
from string import letters
#from comment import Comment

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

secrete = "finger"

def create_secrete_key(my_str):
    keycreated = hmac.new(secrete,my_str).hexdigest()
    return "%s|%s" % (my_str , keycreated)

def check_secrete_key(secrete_val):
    split_val = secrete_val.split("|")[0]
    if secrete_val == create_secrete_key(split_val):
        return split_val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = create_secrete_key(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; path=/' %(name,cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secrete_key(cookie_val)

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; path=/') 

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))  

class Mainpage(BlogHandler):
    def get(self):
        self.write("Welcome to my Blog")

def create_salt(length = 5):
    return ''.join(random.choice(letters) for x in range (length))

def create_hash_password(name,password,salt = None):
    if not salt:
        salt = create_salt()
    hash = hashlib.sha256(name+password+salt).hexdigest()
    return "%s|%s" % (salt,hash)

def valid_hash_password(name,password,hash):
    salt = hash.split('|')[0]
    return hash == create_hash_password(name,password,salt)

def users_key(group = 'default'):
    return db.Key.from_path('users',group)

class User(db.Model):
    name = db.StringProperty(required = True)
    hashed_password = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls,uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def filter_name(cls,name):
        u = User.all().filter('name =' , name).get()
        return u

    @classmethod
    def register(cls, name, password, email = None):
        hashed_password = create_hash_password(name, password)
        return User(parent = users_key(),
                    name = name,
                    hashed_password = hashed_password,
                    email = email)

    @classmethod
    def login(cls,name,password):
        u = cls.filter_name(name)
        if u and valid_hash_password(name,password,u.hashed_password):
            return u
        
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Registration(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")
        error = False

        params = dict(username = self.username, email = self.email)

        
        if not valid_username(self.username):
            params['error_username'] = " That's not a valid username."
            error = True

        if not valid_password(self.password):
            params['error_password'] = " That wasn't a valid password."
            error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class welcomeSignup(Registration):
    def done(self):
        self.redirect('/welcome?username=' + self.username)

class Register(Registration):
    def done(self):
        u = User.filter_name(self.username)
        print("the uuuu is %s" %u)
        if u:
            msg = "User already exist"
            self.render("signup-form.html" , error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            print("username is %s" % self.username)

            self.login(u)
            self.redirect("/blog")

class Login(BlogHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')

        u = User.login(self.username,self.password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = "Invalid username and password"
            self.render("login.html", error = msg)

def blogpage_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Postblog(db.Model):
    user_id = db.IntegerProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        self._render_text = self.content.replace('/n', '<br>')
        return render_str("post.html", p = self) 

class create_Newpost(BlogHandler):
    def get(self):
        if self.user:
            #user_id = User.get_current_user()
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/blog')

        #value = self.request.get('key')
        subject = self.request.get('subject')
        content = self.request.get('content')
        comments = self.request.get('comments')
        
        if subject and content:
            ps = Postblog(parent = blogpage_key(), user_id = self.user.key().id(), subject = subject, content = content)#, value =self.user.key().id()) 
            ps.put()
            self.redirect('/blog/%s' %str(ps.key().id()))

        if comments:
            post_id = self.request.get('post_id')
            cs = Comment(parent = blogpage_key(), comments = comments, user_id = self.user.key().id(), post_id = int(post_id))
            cs.put()
            return self.redirect("/blog/" +post_id)
    
        else:
            error = "Please, enter subject and content"
            self.render("newpost.html", subject = subject, content = content, error = error)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Postblog', int(post_id), parent = blogpage_key())
        post = db.get(key)
        comments = Comment.all()

        if not post:
            self.error(404)
            return
        else:   
            self.render('permalink.html', post = post, comments = comments)


class Blog_front_page(BlogHandler):
    def get(self):
        posts = greetings = Postblog.all().order('-created')
        post_comments = Comment.all().order('created')
        
        self.render("front.html", posts = posts, post_comments = post_comments)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class DeletePost(BlogHandler):
    def post(self, post_id):
        i = self.request.get('key')
        k = db.Key.from_path('Postblog', int(i), parent = blogpage_key())
        del_comment = db.get(k)
        db.delete(del_comment)
        #posts = Postblog.all().order('-created')
        #self.response.out.write("post deleted")
        self.redirect('/?posts='+post_id)

class EditPost(BlogHandler):
    def get(self):
        i = self.request.get('key')
        edit_k = db.Key.from_path('Postblog', int(i), parent = blogpage_key())
        edit = db.get(edit_k)
        if self.user:
            self.render("editpost.html", subject = edit.subject, content = edit.content)
        else:
            self.redirect('/login')
        #else:
            #self.redirect("/blog"+post_id+"?error=You don't have access to edit this record")
        
    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            i = self.request.get('key')
            edit_k = db.Key.from_path('Postblog', int(i), parent = blogpage_key())
            edit = db.get(edit_k)
            edit.subject = subject
            edit.content = content
            edit.put()
            self.redirect('/blog/%s' % i)
        else:
            error = "Please, enter subject and content"
            self.render("editpost.html", subject = subject, content = content, error = error) 



class Comment(db.Model):
    comments = db.StringProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name
    
class fetch_allusers(BlogHandler):
    def get(self):

        if self.user:
            users_posts = Postblog.all().order('-created')

            post_comments = Comment.all().order('-created')

            self.render('likepost.html', users_posts = users_posts, post_comments = post_comments)
             
    def post(self):
        
        users_posts = Postblog.all().order('-created')
            
        post_comments = Comment.all().order('-created')

        comments = self.request.get('comments')

        post_id = self.request.get('post_id')
        key = db.Key.from_path('Postblog', int(post_id), parent = blogpage_key())
        post = db.get(key)

        if comments:
            i = self.request.get('post_id')
            cs = Comment(parent = blogpage_key(), comments = comments, user_id = self.user.key().id() , post_id = int(i))
            cs.put()
            return self.redirect("/blog/" +post_id)

        else:
            comment_error = "please, enter the comment"
            

class delete_Comment(BlogHandler):
    def get(self, post_id, comments_id):
        #i = self.request.get('comment_post_id')
        k = db.Key.from_path('Comment', int(comments_id), parent = blogpage_key())
        comment = db.get(k)
        if comment.user_id == self.user.key().id():
            db.delete(comment)
            self.redirect('/blog/'+post_id)

class EditComment(BlogHandler):
    def get(self, post_id, comments_id):
        k = db.Key.from_path('Comment', int(comments_id), parent = blogpage_key())
        edit = db.get(k)
        if edit.user_id == self.user.key().id():
            self.render('editcomment.html', comments = edit.comments)
        else:
            error = "You cannot edit other's comment"
            self.render('editcomment.html', error = error)

    def post(self, post_id, comments_id):
        comments = self.request.get('comments')
        if comments:
            k = db.Key.from_path('Comment', int(comments_id), parent = blogpage_key())
            edit = db.get(k)
            edit.comments = comments
            edit.put()
            self.redirect('/blog/'+post_id)
        else:
            error = "You cannot edit other's comment"
            self.render('editcomment.html', comments = comments, error = error)

class Like(db.Model):
    post_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class LikePost(BlogHandler):
    def get(self, post_id):
        like_post = db.GqlQuery("select * from Like where post_id=" +post_id)
        print("LLLLLLLLLLLLLL%s" %like_post)
        self.render('front.html', like_post = like_post.count())

    def post(self, post_id):
        p = self.request.get('like_post_id')
        print("OOOOOOOOOOOOOOO%s" %p)
        if self.request.get('like'):
            if self.user:
                count = count
                cs = Like(parent = blogpage_key(), post_id = int(p), user_id = self.user.key().id())
                cs.put()
        self.redirect('front.html', count = count)

        

app = webapp2.WSGIApplication([('/', Mainpage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/?', Blog_front_page),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', create_Newpost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/editpost', EditPost),
                               ('/likepost', fetch_allusers),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)', delete_Comment),
                               ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
                               ('/blog/([0-9]+)/likepost', LikePost),],debug = True)





