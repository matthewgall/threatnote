from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from models import Requirements, RequirementConsumers, User, Consumers,RequirementReports, Reports
from lib import add_db_entry
from main import app
from config import db
from sqlalchemy import func, asc, desc


@app.route('/consumers',methods=['GET'])
@login_required
def view_consumers():
    consumer_dict={}

    org_id=User.query.filter_by(id=current_user.id).first().organization
    consumers=Consumers.query.filter_by(organization=org_id).all()
    for consumer in consumers:
        dict=consumer.__dict__
        dict.pop('_sa_instance_state')
        consumer_dict[consumer.id]=dict
        

        
    #so all we want are min/max dates and counts of reports and reqs, so let's so it the easier way
    ir_counts=(db.session.query(RequirementConsumers.consumer,func.count(RequirementConsumers.requirement),  func.min(Requirements.created_at), func.max(Requirements.updated_at))
        .join(Requirements, RequirementConsumers.requirement==Requirements.id)
        .filter(RequirementConsumers.consumer.in_(consumer_dict.keys() ))
        .group_by(RequirementConsumers.consumer)
        .all())
    print(ir_counts)
    for result in ir_counts:
        consumer=consumer_dict.get(result[0],{})
        consumer['num_of_reqs']=result[1]
        consumer['oldest_req']=result[2]
        consumer['latest_req']=result[3]
        consumer_dict[result[0]]=consumer

    report_counts=(db.session.query(RequirementConsumers.consumer, func.count(RequirementReports.report), func.min(Reports.created_at), func.max(Reports.updated_at))
        .join(RequirementReports, RequirementReports.requirement==RequirementConsumers.requirement)
        .join(Reports, RequirementReports.report==Reports.id)
        .filter(RequirementConsumers.consumer.in_(consumer_dict.keys() ))
        .group_by(RequirementConsumers.consumer)
        .all())

    for result in report_counts:
        consumer=consumer_dict.get(result[0],{})
        consumer['num_of_reports']=result[1]
        consumer['oldest_report']=result[2]
        consumer['latest_report']=result[3]
        consumer_dict[result[0]]=consumer
        
    for id in consumer_dict:
        if 'num_of_reports' not in consumer_dict[id]:
            consumer_dict[id]['num_of_reports']=0
        if 'num_of_reqs' not in consumer_dict[id]:
            consumer_dict[id]['num_of_reqs']=0

    return render_template('consumers.html',consumers=consumer_dict.values(),page_title='Consumers')

@app.route('/edit_consumer/<consumer_id>')
@login_required
def edit_consumer(consumer_id):
    consumer = Consumers.query.filter_by(id=consumer_id).first()
    return render_template('edit_consumer.html',consumer=consumer)

@app.route('/edit_consumer/<consumer_id>',methods=['POST'])
@login_required
def update_consumer(consumer_id):
    args = request.form
    subtitle = args.get('subtitle')
    email = args.get('email')
    poc = args.get('poc')
    Consumers.query.filter_by(id=consumer_id).update({'subtitle':subtitle,'email':email,'poc':poc})
    db.session.commit()
    db.session.flush()
    return redirect('/consumers')

