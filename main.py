from sqlite3 import IntegrityError
from flask import Flask, json, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask.helpers import url_for
from flask.globals import request, session
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, logout_user, login_user, login_manager, LoginManager, current_user
from flask_mail import Mail
import json

#mydatabase connection
local_server = True
app = Flask(__name__)
app.secret_key = "mdatheeq"

with open("config.json", 'r') as c:
    params = json.load(c)["params"]

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT='465',
    MAIL_USE_SSL=True,
    MAIL_USERNAME=params['gmail-user'],
    MAIL_PASSWORD=params['gmail-password']
)
mail = Mail(app)

# This is for getting the unique user access
login_manager = LoginManager(app)
login_manager.login_view = 'login'


app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@localhost/covid"
db = SQLAlchemy(app)

# @login_manager.user_loader
# def load_user(user_id):
#      return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return Hospitaluser.query.get(int(user_id))



class Test(db.Model):
    id = db.Column(db.Integer, primary_key = True)  
    name = db.Column(db.String(50))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    srfid = db.Column(db.String(20), unique = True)
    email = db.Column(db.String(40))
    password = db.Column(db.String(1000))

class Hospitaluser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    hcode = db.Column(db.String(20), unique = True)
    email = db.Column(db.String(40))
    password = db.Column(db.String(1000))


class Hospitaldata(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    hcode=db.Column(db.String(20),unique=True)
    hname=db.Column(db.String(100))
    normalbed=db.Column(db.Integer)
    hicubed=db.Column(db.Integer)
    icubed=db.Column(db.Integer)
    vbed=db.Column(db.Integer)


class Bookingpatient(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    srfid=db.Column(db.String(20),unique=True)
    bedtype=db.Column(db.String(100))
    hcode=db.Column(db.String(20))
    spo2=db.Column(db.Integer)
    pname=db.Column(db.String(100))
    pphone=db.Column(db.String(100))
    paddress=db.Column(db.String(100))


class Trig(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    hcode=db.Column(db.String(20))
    normalbed=db.Column(db.Integer)
    hicubed=db.Column(db.Integer)
    icubed=db.Column(db.Integer)
    vbed=db.Column(db.Integer)
    querys=db.Column(db.String(50))
    date=db.Column(db.String(50))





@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods = ['POST', 'GET'])
def signup():
    if request.method == "POST":
        srfid = request.form.get('srf')
        email = request.form.get('email')
        password = request.form.get('password')
        encpassword = generate_password_hash(password)
        user=User.query.filter_by(srfid=srfid).first()
        emailUser=User.query.filter_by(email=email).first()
        if user or emailUser:
            flash("Email or srif is already taken","warning")
            return render_template("usersignup.html")
        new_user = User(srfid=srfid, email=email, password=encpassword)
        db.session.add(new_user)
        db.session.commit()
        flash("SignUp Success Please Login","success")
        return render_template("userlogin.html")
    return render_template("usersignup.html")


@app.route("/login", methods = ['POST', 'GET'])
def login():
    if request.method == "POST":
        srfid = request.form.get('srf')
        password = request.form.get('password')
        user = User.query.filter_by(srfid = srfid).first()
        if user and check_password_hash(user.password, password):
             login_user(user)
             flash("login success","info")
             return render_template("index.html")
        else:
             flash("Invalid Credentials","danger")
             return render_template("userlogin.html")
    return render_template("userlogin.html")

@app.route("/admin", methods = ['POST', 'GET'])
def admin():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username == params["user"] and password == params["password"]:
            session["user"] = username
            flash("login success", "info")
            return render_template("addHosUser.html")
        else:
            flash("Invalid Credentials","danger")
    return render_template("admin.html")

@app.route("/addHospitalUser", methods=['POST', 'GET'])
def hospitalUser():
    if 'user' in session and session['user'] == params['user']:
        if request.method == "POST":
            hcode = request.form.get('hcode').upper()
            email = request.form.get('email')
            password = request.form.get('password')
            encpassword = generate_password_hash(password)

            # Check if the email or hcode already exists
            existing_hcode = Hospitaluser.query.filter_by(hcode=hcode).first()
            emailUser = Hospitaluser.query.filter_by(email=email).first()
            if existing_hcode:
                flash("Hospital code is already taken", "warning")
                return render_template("addHosUser.html")
            if emailUser:
                flash("Email is already taken", "warning")
                return render_template("addHosUser.html")

            try:
                query = Hospitaluser(hcode=hcode, email=email, password=encpassword)
                db.session.add(query)
                db.session.commit()

                # Send credentials to the hospital user
                mail.send_message(
                    'COVID CARE CENTER',
                    sender=params['gmail-user'],
                    recipients=[email],
                    body=f"Welcome, thanks for choosing us.\nYour Login Credentials Are:\n Email Address: {email}\nPassword: {password}\n\nHospital Code: {hcode}\n\nDo not share your password.\n\nThank You..."
                )

                flash("Data Sent and Inserted Successfully", "success")
                return render_template("addHosUser.html")

            except IntegrityError as e:
                db.session.rollback()
                flash(f"Error: {str(e.orig)}", "danger")
                return render_template("addHosUser.html")
    else:
        flash("Login and try again", "warning")
        return render_template("addHosUser.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout SuccessFul","warning")
    return redirect(url_for('login'))

@app.route("/logoutadmin")
def logoutadmin():
    session.pop('user')
    flash("You are logout admin", "primary")
    return redirect('/admin')

@app.route("/hospitallogin", methods = ['POST', 'GET'])
def hospitallogin():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = Hospitaluser.query.filter_by(email = email).first()
        if user and check_password_hash(user.password, password):
             login_user(user)
             flash("login success","info")
             return render_template("index.html")
        else:
             flash("Invalid Credentials","danger")
             return render_template("hospitallogin.html")
    return render_template("hospitallogin.html")

@app.route("/addhospitalinfo", methods=['POST', 'GET'])
@login_required
def addhospitalinfo():
    if current_user.is_authenticated and isinstance(current_user, Hospitaluser):
        email = current_user.email
        posts = Hospitaluser.query.filter_by(email=email).first()

        if posts is None:
            flash("Hospital user not found.", "warning")
            return redirect(url_for('hospitallogin'))

        code = posts.hcode
        postsdata = Hospitaldata.query.filter_by(hcode=code).first()

        if request.method == "POST":
            hcode = request.form.get('hcode').upper()
            hname = request.form.get('hname')
            nbed = request.form.get('normalbed')
            hbed = request.form.get('hicubeds')
            ibed = request.form.get('icubeds')
            vbed = request.form.get('ventbeds')

            hduser = Hospitaldata.query.filter_by(hcode=hcode).first()
            if hduser:
                flash("Data is already present. You can update it.", "primary")
                return render_template("hospitaldata.html", postsdata=postsdata)

            huser = Hospitaluser.query.filter_by(hcode=hcode).first()
            if huser:
                new_hospital_data = Hospitaldata(hcode=hcode, hname=hname, normalbed=nbed, hicubed=hbed, icubed=ibed, vbed=vbed)
                db.session.add(new_hospital_data)
                db.session.commit()
                flash("Data is added", "primary")
                return redirect('/addhospitalinfo')
            else:
                flash("Hospital code does not exist", "warning")
                return redirect('/addhospitalinfo')

        return render_template("hospitaldata.html", postsdata=postsdata)
    else:
        flash("Unauthorized access", "danger")
        return redirect(url_for('hospitallogin'))
    


@app.route("/hedit/<string:id>",methods=['POST','GET'])
@login_required
def hedit(id):
    posts=Hospitaldata.query.filter_by(id=id).first()
  
    if request.method=="POST":
        hcode=request.form.get('hcode')
        hname=request.form.get('hname')
        nbed=request.form.get('normalbed')
        hbed=request.form.get('hicubeds')
        ibed=request.form.get('icubeds')
        vbed=request.form.get('ventbeds')
        hcode=hcode.upper()
        # db.engine.execute(f"UPDATE `hospitaldata` SET `hcode` ='{hcode}',`hname`='{hname}',`normalbed`='{nbed}',`hicubed`='{hbed}',`icubed`='{ibed}',`vbed`='{vbed}' WHERE `hospitaldata`.`id`={id}")
        post=Hospitaldata.query.filter_by(id=id).first()
        post.hcode=hcode
        post.hname=hname
        post.normalbed=nbed
        post.hicubed=hbed
        post.icubed=ibed
        post.vbed=vbed
        db.session.commit()
        flash("Slot Updated","info")
        return redirect("/addhospitalinfo")

    # posts=Hospitaldata.query.filter_by(id=id).first()
    return render_template("hedit.html",posts=posts)



@app.route("/hdelete/<string:id>",methods=['POST','GET'])
@login_required
def hdelete(id):
    # db.engine.execute(f"DELETE FROM `hospitaldata` WHERE `hospitaldata`.`id`={id}")
    post=Hospitaldata.query.filter_by(id=id).first()
    db.session.delete(post)
    db.session.commit()
    flash("Data Deleted","danger")
    return redirect("/addhospitalinfo")


@app.route("/slotbooking", methods=['POST', 'GET'])
@login_required
def slotbooking():
    query1 = Hospitaldata.query.all()
    query = Hospitaldata.query.all()
    
    if request.method == "POST":
        srfid = request.form.get('srfid')
        bedtype = request.form.get('bedtype')
        hcode = request.form.get('hcode')
        spo2 = request.form.get('spo2')
        pname = request.form.get('pname')
        pphone = request.form.get('pphone')
        paddress = request.form.get('paddress')
        
        check2 = Hospitaldata.query.filter_by(hcode=hcode).first()
        checkpatient = Bookingpatient.query.filter_by(srfid=srfid).first()
        
        if checkpatient:
            flash("Already srf id is registered", "warning")
            return render_template("booking.html", query=query, query1=query1)
        
        if not check2:
            flash("Hospital Code does not exist", "warning")
            return render_template("booking.html", query=query, query1=query1)
        
        dbb = Hospitaldata.query.filter_by(hcode=hcode).first()
        
        if dbb:
            if bedtype == "NormalBed":
                seat = dbb.normalbed
                if seat > 0:
                    dbb.normalbed = seat - 1
            elif bedtype == "HICUBed":
                seat = dbb.hicubed
                if seat > 0:
                    dbb.hicubed = seat - 1
            elif bedtype == "ICUBed":
                seat = dbb.icubed
                if seat > 0:
                    dbb.icubed = seat - 1
            elif bedtype == "VENTILATORBed":
                seat = dbb.vbed
                if seat > 0:
                    dbb.vbed = seat - 1
            else:
                seat = 0
            
            if seat > 0:
                db.session.commit()
                res = Bookingpatient(srfid=srfid, bedtype=bedtype, hcode=hcode, spo2=spo2, pname=pname, pphone=pphone, paddress=paddress)
                db.session.add(res)
                db.session.commit()
                flash("Slot is booked. Kindly visit hospital for further procedure", "success")
            else:
                flash("No available beds of the selected type", "danger")
        else:
            flash("Hospital Code does not exist", "warning")
        
        return render_template("booking.html", query=query, query1=query1)
    
    return render_template("booking.html", query=query, query1=query1)



@app.route("/pdetails", methods=['GET'])
@login_required
def pdetails():
    if isinstance(current_user, User):
        code = current_user.srfid
        data = Bookingpatient.query.filter_by(srfid=code).first()
    elif isinstance(current_user, Hospitaluser):
        code = current_user.hcode
        data = Hospitaldata.query.filter_by(hcode=code).first()
    else:
        data = None
        flash("Unauthorized access", "danger")
    
    return render_template("detials.html", data=data)


if __name__ == "__main__":
    app.run(debug=True)
