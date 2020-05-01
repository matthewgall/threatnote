from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from models import Indicators,  Reports, Links, User
from lib import add_db_entry, get_comments, get_user_info
from main import app, parse_indicators, queue
from config import db
from sqlalchemy import func, asc, desc


@app.route('/indicators')
@login_required
def view_indicators():
    indicators = Indicators.query.filter_by().all()
    #what the heck to do about confidence and kill_chain????
    return render_template('/indicators.html',indicators=indicators,page_title="Indicators")

@app.route('/refresh_indicator/<indicator_id>/<report_id>')
@login_required
def refresh_indicator(indicator_id,report_id):
    indicator_info = Indicators.query.filter_by(id=indicator_id).all()
    result_dict = [u.__dict__ for u in indicator_info]
    parse_indicators(str(result_dict[0]['indicator']),report_id, queue)
    return redirect('/report/'+report_id)
    
@app.route('/edit_indicator/<indicator_id>')
@login_required
def edit_indicator(indicator_id):
    indicator_info = Indicators.query.filter_by(id=indicator_id).first()
    #result_dict = [u.__dict__ for u in indicator_info]
    #diamondStatus = ['Adversary', 'Infra', 'Victim' ,'Capability','Unknown']
    #default = 'Unknown'
    #killchainStatus = ['Recon','Weaponization','Delivery','Exploitation','Installation','C2','Actions on Objectives','Unknown']
    related_reports=[]
    links=(db.session.query(Reports, Links)
                     .join(Links, Links.report==Reports.id)
                     .filter(Links.indicator==indicator_id)
                     .order_by(desc(Reports.updated_at))
                     .all()
                     )
    for report, link in links:
        rep=report.__dict__
        rep['confidence']=link.confidence
        rep['kill_chain']=link.kill_chain
        rep['diamond_model']=link.diamond_model
        related_reports.append(rep)
    
    indicator_details = indicator_info.__dict__


    
    return render_template('edit_indicator.html',
                           indicator=indicator_info.__dict__, 
                           #diamondStatus=diamondStatus, 
                           #killchainStatus=killchainStatus,
                           comments=get_comments(indicator_id=indicator_id), 
                           #default=default,
                           related_reports=related_reports,
                           user_info=get_user_info(current_user.id),
                           user_id=current_user.id,page_title=indicator_details.get('indicator'))

@app.route('/update_indicator/<indicator_id>/<report_id>',methods=['POST'])
@login_required
def update_indicator(indicator_id, report_id):
    print('{} {}'.format(indicator_id, report_id))
    form_data = request.form
    report_indicator=Links.query.filter_by(report=report_id).filter_by(indicator=indicator_id).first()
    if report_indicator:
        print('link found')
        if form_data.get('kill_chain'):
            print('kill chain {}'.format(form_data.get('kill_chain')))

            report_indicator.kill_chain=form_data.get('kill_chain')
        if form_data.get('confidence'):
            print('confidence {}'.format(form_data.get('confidence')))

            report_indicator.confidence=form_data.get('confidence')
        if form_data.get('diamond_model'):
            print('diamond_model {}'.format(form_data.get('diamond_model')))

            report_indicator.diamond_model=form_data.get('diamond_model')
        db.session.commit()
        db.session.flush()
        
    else:
        report_indicator=Links(report=report_id,indicator=indicator_id)
        report_indicator.kill_chain=form_data.get('kill_chain', 'Unknown')
        report_indicator.confidence=form_data.get('confidence', 'Low')
        report_indicator.diamond_model=form_data.get('diamond_model', 'Unknown')
        add_db_entry(report_indicator)
    return 'success'
