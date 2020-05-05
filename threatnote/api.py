from  main import app
from  main import db
from  models import User, Indicators, Links

from flask import request, redirect, jsonify 
from flask_login import current_user, login_user
from werkzeug.security import check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

import traceback
import json

#set to false if no authentication
AUTHENTICATE_API_CALLS=True

TOKEN_EXPIRATION = 60*60

'''
User can authenticate using basic authentication, 
passing email and password through query parameters, 
passing email and password through posted json, 
passing a token through query parameters
passing a token through hrough posted json

Returns a User object if authenticated
'''
def authenticate_credentials(request):
    api_key=None
    
    if current_user.is_authenticated:
        id=current_user.get_id()
        user=User.query.get(id)    
        return user
    else:
        if request.authorization:
            api_key = request.authorization.get('api_key')
        elif 'api_key' in request.form:
            api_key=request.form.get('api_key')
        elif 'api_key' in request.args:
            api_key=request.args.get('api_key')
        elif request.get_json():
            data=request.get_json()
            api_key=data.get('api_key')
        
        if api_key:
            user=User.query.filter_by(tn_api_key=api_key).first()
            if user:
                #print(user.id)
                #login_user(user)
                return user
    return None

'''
This returns a list of indicators
Args-
(optional)report_id - only indicators linked to a certain report
(optional) email and password - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
(optional) token - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
'''
@app.route('/api/indicators', methods=['GET'])
def api_indicators_list(report_id=None):
    try:
        user=None
        if AUTHENTICATE_API_CALLS:
            user=authenticate_credentials(request)
        if user or not AUTHENTICATE_API_CALLS:
            if not report_id :
                report_id=request.args.get('report_id')
            if report_id:
                indicators=db.session.query(Indicators).join(Links, Indicators.id == Links.indicator).filter(Links.report == report_id).order_by(Indicators.indicator).all()
            else:
                indicators=db.session.query(Indicators).join(Links, Indicators.id == Links.indicator).order_by(Indicators.indicator).all()
            indicator_list=[]
            for indicator in indicators:
                indicator_dict=indicator.__dict__
                indicator_dict.pop('_sa_instance_state')
                indicator_list.append(indicator_dict)
            return jsonify(indicator_list)
        
        
        resp = jsonify({'message' : 'unauthorized'})
        resp.status_code = 401
        return resp

    except Exception as err:
        tb = traceback.format_exc()
        print(tb)
        resp = jsonify({'message' : 'An error occurred', 'error':str(err)})
        resp.status_code = 503
        return resp


'''
This returns a single indicator
Args-
indcator_id - indicator_id or indicator name- can use either
(optional) email and password - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
(optional) token - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
'''
@app.route('/api/indicators/<indicator_id>', methods=['GET'])
def api_indicator_get(indicator_id):
    try:
        user=None
        if AUTHENTICATE_API_CALLS:
            user=authenticate_credentials(request)
        if user or not AUTHENTICATE_API_CALLS:
            try:
                indicator=db.session.query(Indicators).filter(Indicators.id == int(indicator_id)).first()
            except ValueError:
                indicator=db.session.query(Indicators).filter(Indicators.indicator == indicator_id).first()
                
            if indicator:
                indicator_dict=indicator.__dict__
                indicator_dict.pop('_sa_instance_state')
            else:
                indicator_dict={}
            return jsonify(indicator_dict)

        resp = jsonify({'message' : 'unauthorized'})
        resp.status_code = 401
        return resp

    except Exception as err:
        tb = traceback.format_exc()
        print(tb)
        resp = jsonify({'message' : 'An error occurred', 'error':str(err)})
        resp.status_code = 503
        return resp

@app.route('/api/login', methods=['GET','POST'])
def api_get_token():
    user=authenticate_credentials(request)
    if user:
        s = Serializer(app.config['SECRET_KEY'], expires_in=TOKEN_EXPIRATION)
        token=s.dumps({'id': user.id})
        return jsonify({'token': token.decode('ascii'),'expires_in':TOKEN_EXPIRATION})
    
    resp = jsonify({'message' : 'unauthorized'})
    resp.status_code = 401
    return resp
