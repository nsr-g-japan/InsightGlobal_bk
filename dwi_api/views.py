import requests
from azure.storage.blob import BlockBlobService
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse

import adal
import time
import pandas as pd
import uuid
from sqlalchemy import create_engine
import sqlalchemy as sa

import mysql.connector
import psycopg2

import xmltodict
import json

from datetime import datetime
import random
# define the random module

gl_db_server = 'gjndev.database.windows.net'
gl_db_name = 'dwi_api'
gl_db_username = 'gindev'
gl_db_password = 'admin@123'
connection_url = sa.engine.URL.create(
    "mssql+pyodbc",
    username=gl_db_username,
    password=gl_db_password,
    host=gl_db_server,
    database=gl_db_name,
    query={
        "driver": "ODBC Driver 17 for SQL Server",
        "autocommit": "True",
    },
)


# getting random string for session key usage
def get_random_string():
    # define the specific string
    sample_string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-0123456789.~$^'
    # define the condition for random string
    str1 = ''.join((random.choice(sample_string)) for x in range(127))
    str2 = ''.join((random.choice(sample_string)) for x in range(127))
    # datetime object containing current date and time
    now = str(datetime.now()).replace(' ', '').replace('-', '').replace(':', '')
    rand_string = str(str1) + str(now) + str(str2)  # print the random data
    return rand_string


# getting session auth key if not avail then create and send new one
def get_auth_key(token, refresh_token, user_email):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM api_sessions_log WHERE azsl_access_token LIKE '""" + token + """' 
        AND azsl_refresh_token LIKE '""" + refresh_token + """' AND azsl_user_email = '""" + user_email + """'"""
    table_list = engine.execute(select_qry).fetchall()

    if len(table_list) == 0:
        azsl_session_token = get_random_string()
        ins_qry = """INSERT INTO api_sessions_log (azsl_session_token, azsl_user_email, azsl_access_token, 
        azsl_refresh_token) VALUES ('""" + azsl_session_token + """', '""" + user_email + """',  '""" + token + """', 
            '""" + refresh_token + """')"""
        engine.execute(ins_qry)

        select_qry = """SELECT * FROM api_sessions_log WHERE azsl_access_token LIKE '""" + token + """' 
                AND azsl_refresh_token LIKE '""" + refresh_token + """' AND azsl_user_email = '""" + user_email + """'"""
        table_list = engine.execute(select_qry).fetchone()
        return {"session_key": table_list.azsl_session_token, "status_code": 200}
    else:
        select_qry = """SELECT * FROM api_sessions_log WHERE azsl_access_token LIKE '""" + token + """' 
                        AND azsl_refresh_token LIKE '""" + refresh_token + """' AND azsl_user_email = '""" + user_email + """'"""
        table_list = engine.execute(select_qry).fetchone()
        return {"session_key": table_list.azsl_session_token, "status_code": 200}


# getting azure and user token stored in session logs from session key
def get_tokens_from_session_logs(auth_key):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM api_sessions_log WHERE azsl_session_token = '""" + auth_key + """' 
    AND azsl_session_is_active = 1 AND azsl_session_is_expired = 0 """
    table_list = engine.execute(select_qry).fetchone()

    if table_list is None:
        return {"resp": {"error": {"code": "AuthkeyNotValid", "message": "Auth key expired or Not Valid"}},
                "status_code": 404}
    else:
        return {"resp": table_list, "status_code": 200}


# Update session log as expired if user/azure token is expired
def update_session_auth_key_as_expired(auth_key):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    update_qry = """UPDATE api_sessions_log SET azsl_session_is_active = 0, azsl_session_is_expired = 1
    WHERE azsl_session_token = '""" + auth_key + """'"""
    engine.execute(update_qry)

    return {"message": "Session marked as expired and de-activated", "status_code": 200}


# Check user session is valid by their auth_key, check with user/azure token too
def check_user_authentication(auth_key):
    if auth_key == "":
        err_resp = {"is_authenticated": False,
                    "response":
                        {"error":
                             {"code": "invalid_request",
                              "message": "The request body must contain the following parameter: 'auth_key'."
                              }
                         },
                    "status_code": 400}
        return err_resp
    else:
        tokens = get_tokens_from_session_logs(auth_key)
        if tokens['status_code'] != 200:
            err_resp = {"is_authenticated": False, "response": tokens['resp'], "status_code": tokens['status_code']}
            return err_resp
        else:
            azsl_refresh_token = tokens['resp'].azsl_refresh_token
            azsl_access_token = tokens['resp'].azsl_access_token
            user_details = get_user_details_from_graph(azsl_access_token)
            if user_details.status_code != 200:
                update_session_auth_key_as_expired(auth_key)
                err_resp = {"is_authenticated": False,
                            "response":
                                {"error":
                                     {"code": "AccessTokenExpired",
                                      "message": "Access Token expired. Get new Auth key. Session expired"
                                      }
                                 },
                            "status_code": user_details.status_code}
                return err_resp
            else:
                azure_auth_resp = get_azure_subscription_details_from_rest_api(azsl_refresh_token)
                az_status_code = azure_auth_resp.status_code
                if az_status_code != 200:
                    update_session_auth_key_as_expired(auth_key)
                    err_resp = {"is_authenticated": False,
                                "response":
                                    {"error":
                                         {"code": "RefreshTokenExpired",
                                          "message": "Refresh Token expired. Get new Auth key. Session expired"
                                          }
                                     },
                                "status_code": az_status_code}
                    return err_resp
                else:
                    result_resp = {"is_authenticated": True,
                                   "response":
                                       {
                                           "auth_key": auth_key,
                                           "azsl_refresh_token": azsl_refresh_token,
                                           "azsl_access_token": azsl_access_token,
                                           "user_details": user_details.json()
                                       },
                                   "status_code": 200}
                    return result_resp


# Get user details from azure Graph API using access_token
def get_user_details_from_graph(token):
    # Send GET to /me
    user = requests.get('https://graph.microsoft.com/v1.0/me', headers={'Authorization': 'Bearer {0}'.format(token)})
    # Return the JSON result
    return user


# Get Azure management token from user impersonation using refresh_token
def get_azure_management_token(refresh_token):
    # set headers
    headers = {
        'client_id': 'da2d8409-9e4f-437e-a0f2-2171be2736cf',
        'scope': 'https://management.azure.com/user_impersonation',
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
        'client_secret': 'ZIR8Q~ORKWYG7C1jrctKBAxj3PIIgb5qE15pFdv6'
    }
    # Send POST to https://login.microsoftonline.com/common/oauth2/v2.0/token
    result = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=headers)
    return result


# Check token is valid or not by calling Azure Management API services
def get_azure_subscription_details_from_rest_api(token_as_refresh_token):
    # Send GET to /management.azure.com/subscription
    subscriptionList = requests.get('https://management.azure.com/subscriptions?api-version=2020-01-01',
                                    headers={'Authorization': 'Bearer {0}'.format(token_as_refresh_token)})
    # Return the JSON result
    return subscriptionList


# Saving client subscription list in our DB for ease of access
def save_subscription_list(subs):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM az_subscriptions WHERE subscriptionId = '""" + subs['subscriptionId'] + """' 
    AND tenantId = '""" + subs['tenantId'] + """'"""
    table_list = engine.execute(select_qry).fetchall()

    if len(table_list) == 0:
        ins_qry = """INSERT INTO az_subscriptions (subscriptionId, tenantId, id, authorizationSource, displayName, 
        state) VALUES ('""" + subs['subscriptionId'] + """', '""" + subs['tenantId'] + """',  '""" + subs['id'] + """', 
        '""" + subs['authorizationSource'] + """', '""" + subs['displayName'] + """', '""" + subs['state'] + """')"""
        engine.execute(ins_qry)
        return 'Inserted'
    else:
        upd_qry = """UPDATE az_subscriptions SET authorizationSource = '""" + subs['authorizationSource'] + """', 
        displayName = '""" + subs['displayName'] + """', state = '""" + subs['state'] + """'
         WHERE subscriptionId = '""" + subs['subscriptionId'] + """' AND tenantId = '""" + subs['tenantId'] + """'"""
        engine.execute(upd_qry)
        return 'Updated'


# Getting Tenant ID from stored subscription list in our DB
def get_tenant_id_from_subscription_id(subscription_id):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM az_subscriptions WHERE subscriptionId = '""" + subscription_id + """' """
    table_list = engine.execute(select_qry).fetchone()

    if len(table_list) == 0:
        return 'Not Found'
    else:
        return table_list.tenantId


# Saving client Storage list in our DB for ease of access
def save_storage_list(subscription_id, tenant_id, storage):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM az_subscription_storages WHERE subscriptionId = '""" + subscription_id + """' 
    AND tenantId = '""" + tenant_id + """' AND storage_id = '""" + storage['id'] + """' """
    table_list = engine.execute(select_qry).fetchall()

    if len(table_list) == 0:
        ins_qry = """INSERT INTO az_subscription_storages (subscriptionId, tenantId, storage_id, storage_name, 
        storage_type, storage_location) VALUES ('""" + subscription_id + """', 
        '""" + tenant_id + """', '""" + storage['id'] + """', '""" + storage['name'] + """', 
        '""" + storage['type'] + """', '""" + storage['location'] + """')"""
        engine.execute(ins_qry)
        return 'Inserted'
    else:
        upd_qry = """UPDATE az_subscription_storages SET storage_name = '""" + storage['name'] + """', 
        storage_type = '""" + storage['type'] + """', storage_location = '""" + storage['location'] + """'
         WHERE subscriptionId = '""" + subscription_id + """' AND tenantId = '""" + tenant_id + """' 
         AND storage_id = '""" + storage['id'] + """'"""
        engine.execute(upd_qry)
        return 'Updated'


# Getting BLOB Access Key from stored Storage list in our DB
def get_blob_access_key(storage_id):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    select_qry = """SELECT * FROM az_subscription_storages WHERE storage_id = '""" + storage_id + """' """
    table_list = engine.execute(select_qry).fetchone()

    return table_list


# Saving BLOB Access Key in Storage list of our DB for ease of access and to upload/download blobs
def save_blob_access_key(storage_id, blob_access_key):
    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )

    ins_qry = """UPDATE az_subscription_storages SET storage_access_key = '""" + blob_access_key + """'
    WHERE storage_id = '""" + storage_id + """'"""
    engine.execute(ins_qry)

    select_qry = """SELECT * FROM az_subscription_storages WHERE storage_id = '""" + storage_id + """'"""
    table_list = engine.execute(select_qry).fetchone()
    if table_list.storage_access_key is None or table_list.storage_access_key != blob_access_key:
        return {"resp": {"error": {"code": "StorageKeyNotUpdated", "message": "Storage Account key is not updated."}},
                "status_code": 500}
    else:
        return {"resp": {"message": "Successfully Updated"}, "status_code": 200}


#connect to DB
def update_db_connection_in_db(id, db_server_unq_name, db_server_host, db_username, db_password, db_port,
                                                db_name, db_type, user_email):
    try:
        engine = create_engine(connection_url).execution_options(isolation_level="AUTOCOMMIT")

        selectqry = """SELECT * FROM db_config WHERE dbc_created_by = '""" + user_email + """'
                    AND dbc_id= '""" + id + """'"""
        table_list = engine.execute(selectqry).fetchall()

        if len(table_list) > 0:
            update_qry = """UPDATE db_config SET dbc_server_unq_name ='""" + db_server_unq_name + """',
                        dbc_server_host = '""" + db_server_host + """', dbc_username = '""" + db_username + """',
                        dbc_password = '""" + db_password + """', dbc_port = '""" + db_port + """',
                        dbc_name = '""" + db_name + """', dbc_type = '""" + db_type + """',
                        dbc_created_by = '""" + user_email + """'
                        WHERE dbc_created_by = '""" + user_email + """'
                        AND dbc_id = '""" + id + """'"""
            engine.execute(update_qry)
            return {"resp": {"message": "DB Config Updated Successfully"}, "status_code": 200}
    except:
        return {"resp": {"error": {"code": "InvalidConfigDetails",
                                   "message": "Not valid Input (OR) DB config is not able to connect."}
                         }, "status_code": 400}


# Connect to DB
def store_db_connection_in_db(db_server_unq_name, db_server_host, db_username, db_password, db_port, db_name, db_type,
                              user_email):
    if db_type == "mssql":
        res = connect_to_mssql(db_server_host, db_username, db_password, db_name)
    elif db_type == "mysql":
        res = connect_to_mysql(db_server_host, db_username, db_password, db_name)
    else:
        res = False

    if not res:
        return {"resp": {"error": {"code": "InvalidConfigDetails",
                                   "message": "Not a valid DB config details. Unable to connect."}
                         }, "status_code": 400}
    else:
        try:
            engine = create_engine(connection_url).execution_options(isolation_level="AUTOCOMMIT")

            selectqry = """SELECT * FROM db_config WHERE dbc_created_by = '""" + user_email + """'
                        AND dbc_server_host = '""" + db_server_host + """'
                        AND dbc_username = '""" + db_username + """'
                        AND dbc_password = '""" + db_password + """'
                        AND dbc_port = '""" + db_port + """'
                        AND dbc_name = '""" + db_name + """'
                        AND dbc_type = '""" + db_type + """'"""
            table_list = engine.execute(selectqry).fetchall()

            if len(table_list) == 0:
                insqry = """INSERT INTO db_config (dbc_server_unq_name, dbc_server_host, dbc_username, dbc_password,
                dbc_port, dbc_name, dbc_type, dbc_created_by) VALUES ('""" + db_server_unq_name + """',
                '""" + db_server_host + """', '""" + db_username + """', '""" + db_password + """', '""" + db_port + """',
                '""" + db_name + """', '""" + db_type + """', '""" + user_email + """')"""
                engine.execute(insqry)
                return {"resp": {"message": "DB Config Saved Successfully"}, "status_code": 200}
        except:
            return {"resp": {"error": {"code": "InvalidConfigDetails",
                                       "message": "Not valid Input (OR) DB config is not able to connect."}
                             }, "status_code": 400}


def connect_to_mssql(server, username, password, database):
    try:
        connection_url = sa.engine.URL.create(
            "mssql+pyodbc",
            username=username,
            password=password,
            host=server,
            database=database,
            query={
                "driver": "ODBC Driver 17 for SQL Server",
                "autocommit": "True",
            },
        )

        engine = create_engine(connection_url).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        schema_qry = "SELECT schema_name(t.schema_id) as schema_name, t.name as table_name " \
                     "FROM sys.tables t order by schema_name, table_name"
        table_list = engine.execute(schema_qry).fetchall()
        return table_list
    except:
        return False


# check schema and tbl exisit in MSSQL DB
def check_schema_and_table_exist_mssql(server, username, password, database, schema_name, table_name):
    connection_url = sa.engine.URL.create(
        "mssql+pyodbc",
        username=username,
        password=password,
        host=server,
        database=database,
        query={
            "driver": "ODBC Driver 17 for SQL Server",
            "autocommit": "True",
        },
    )

    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    chk_qry = "SELECT schema_name(t.schema_id) as schema_name, t.name as table_name " \
              "FROM sys.tables t WHERE schema_name(t.schema_id) = '"+schema_name+"' AND t.name = '"+table_name+"'" \
              "ORDER BY schema_name, table_name"
    table_list = engine.execute(chk_qry).fetchall()
    return table_list


# check schema and tbl exisit in MYSQL DB
def check_schema_and_table_exist_mysql(server, username, password, database, schema_name, table_name, port):
    mydb = mysql.connector.connect(
        host=server,
        user=username,
        password=password,
        port=port
    )

    mycursor = mydb.cursor()
    sql_qry = "SELECT table_schema as schema_name, table_name as table_name " \
              "FROM information_schema.tables " \
              "WHERE table_schema = '" + schema_name + "' AND table_name = '" + table_name + "'"
    mycursor.execute(sql_qry)
    table_list = mycursor.fetchall()
    tl = []
    for value in table_list:
        tmp = {}
        for (index, column) in enumerate(value):
            tmp[mycursor.description[index][0]] = column
        tl.append(tmp)
    return tl


def connect_to_mysql(server, username, password, database):
    try:
        mydb = mysql.connector.connect(
            host=server,
            user=username,
            password=password,
            database=database
        )

        mycursor = mydb.cursor()
        sql_qry = "SELECT table_schema as schema_name, table_name as table_name " \
                  "FROM information_schema.tables WHERE table_schema = '" + database + "'"
        mycursor.execute(sql_qry)
        table_list = mycursor.fetchall()
        tl = []
        for value in table_list:
            tmp = {}
            for (index, column) in enumerate(value):
                tmp[mycursor.description[index][0]] = column
            tl.append(tmp)
        return tl
    except:
        return False


def connect_to_postgres(server, username, password, database):
    conn = psycopg2.connect(
        host=server,
        database=database,
        user=username,
        password=password)

    cur = conn.cursor()
    cur.execute(
        "SELECT table_schema as schema_name, table_name as table_name FROM information_schema.tables WHERE table_schema not in ('pg_catalog','information_schema')")
    table_list = cur.fetchall()
    return table_list


def get_mssql_tbl_schema(server, username, password, database, tblname, tblschema):
    connection_url = sa.engine.URL.create(
        "mssql+pyodbc",
        username=username,
        password=password,
        host=server,
        database=database,
        query={
            "driver": "ODBC Driver 17 for SQL Server",
            "autocommit": "True",
        },
    )

    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )

    selectqry = """SELECT COLUMN_NAME, DATA_TYPE AS COLUMN_TYPE, DATA_TYPE, REPLACE(REPLACE(COLUMN_DEFAULT,'(',''),')','') AS COLUMN_DEFAULT,
            CHARACTER_MAXIMUM_LENGTH AS max_len 
            FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '""" + tblname + """'"""
    table_list = engine.execute(selectqry).fetchall()
    return table_list


def get_mssql_tbl_records(server, username, password, database, tblname, tblschema):
    connection_url = sa.engine.URL.create(
        "mssql+pyodbc",
        username=username,
        password=password,
        host=server,
        database=database,
        query={
            "driver": "ODBC Driver 17 for SQL Server",
            "autocommit": "True",
        },
    )

    engine = create_engine(connection_url).execution_options(
        isolation_level="AUTOCOMMIT"
    )

    selectqry = """SELECT * FROM """ + tblschema + """.""" + tblname
    table_list = engine.execute(selectqry).fetchall()
    return table_list


def get_mysql_tbl_schema(server, username, password, database, port, tblname):
    mydb = mysql.connector.connect(
        host=server,
        user=username,
        password=password,
        port=port
    )

    mycursor = mydb.cursor()
    mycursor.execute(
        "SELECT `COLUMN_NAME`,`COLUMN_TYPE`,`DATA_TYPE`,`COLUMN_DEFAULT`, "
        "IFNULL(CHARACTER_MAXIMUM_LENGTH,SUBSTRING_INDEX(SUBSTRING_INDEX(COLUMN_TYPE, '(', -1), ')', 1)) AS max_len "
        "FROM `INFORMATION_SCHEMA`.`COLUMNS` "
        "WHERE `TABLE_SCHEMA`= '" + database + "' AND `TABLE_NAME`= '" + tblname + "'")
    table_list = mycursor.fetchall()
    return table_list


def get_mysql_tbl_records(server, username, password, database, port, tblname):
    mydb = mysql.connector.connect(
        host=server,
        user=username,
        password=password,
        database=database,
        port=port
    )

    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM " + tblname)
    table_list = mycursor.fetchall()
    return table_list


def get_table_records(dbc_id, tbl_schema, tbl_name, user_email):
    engine = create_engine(connection_url).execution_options(isolation_level="AUTOCOMMIT")

    selectqry = """SELECT * FROM db_config WHERE dbc_id = '""" + dbc_id + """' AND dbc_created_by = '""" + user_email + """'"""
    db_list = engine.execute(selectqry).fetchone()

    if db_list is None or len(db_list) == 0:
        return {"resp": {"error": {"code": "InvalidID",
                                   "message": "Not a valid ID (OR) ID removed."}
                         }, "status_code": 400}
    else:
        if db_list.dbc_type == 'mssql':
            conn_string_check = check_schema_and_table_exist_mssql(db_list.dbc_server_host, db_list.dbc_username,
                                                                   db_list.dbc_password, db_list.dbc_name, tbl_schema, 
                                                                   tbl_name)
            if conn_string_check is None or len(conn_string_check) == 0:
                return {"resp": {"error": {"code": "InvalidDetails",
                                           "message": "Not a Valid Schema Name (OR) Table Name."}
                                 }, "status_code": 400}
            else:
                table_keys = get_mssql_tbl_schema(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                                  db_list.dbc_name, tbl_name, tbl_schema)
                table_list = get_mssql_tbl_records(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                                   db_list.dbc_name, tbl_name, tbl_schema)
                return {"resp": {"column_names": table_keys, "row_values": table_list}, "status_code": 200}
        elif db_list.dbc_type == 'mysql':
            conn_string_check = check_schema_and_table_exist_mysql(db_list.dbc_server_host, db_list.dbc_username,
                                                                   db_list.dbc_password, db_list.dbc_name, tbl_schema,
                                                                   tbl_name, db_list.dbc_port)
            if conn_string_check is None or len(conn_string_check) == 0:
                return {"resp": {"error": {"code": "InvalidDetails",
                                           "message": "Not a Valid Schema Name (OR) Table Name."}
                                 }, "status_code": 400}
            else:
                table_keys = get_mysql_tbl_schema(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                                  db_list.dbc_name, db_list.dbc_port, tbl_name)
                table_list = get_mysql_tbl_records(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                                   db_list.dbc_name, db_list.dbc_port, tbl_name)

                return {"resp": {"column_names": table_keys, "row_values": "table_list"}, "status_code": 200}
        else:
            return {"resp": {"error": {"code": "InvalidDetails",
                                       "message": "Not a Valid DB Type."}
                             }, "status_code": 400}


# Check DB Connection String by ID
def check_db_connection_by_id(dbc_id, user_email):
    engine = create_engine(connection_url).execution_options(isolation_level="AUTOCOMMIT")

    selectqry = """SELECT * FROM db_config WHERE dbc_id = '""" + dbc_id + """' 
    AND dbc_created_by = '""" + user_email + """'"""
    db_list = engine.execute(selectqry).fetchone()

    if db_list is None or len(db_list) == 0:
        return {"resp": {"error": {"code": "InvalidID",
                                   "message": "Not a valid ID (OR) ID removed."}
                         }, "status_code": 400}
    else:

        if db_list.dbc_type == 'mssql':
            table_list = connect_to_mssql(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                          db_list.dbc_name)
        if db_list.dbc_type == 'mysql':
            table_list = connect_to_mysql(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                          db_list.dbc_name)
        if db_list.dbc_type == 'postgres':
            table_list = connect_to_postgres(db_list.dbc_server_host, db_list.dbc_username, db_list.dbc_password,
                                             db_list.dbc_name)
        return {"resp": table_list, "status_code": 200}


# Moving BLOB to MSSQL
def move_to_msql(dbc_id, token, acc_name, container_name, blob_name, schema_name, sheet_indices):
    engine = create_engine(connection_url).execution_options(isolation_level="AUTOCOMMIT")
    selectqry = """SELECT * FROM db_config WHERE dbc_id = '""" + dbc_id + """' AND dbc_type = 'mssql'"""
    db_list = engine.execute(selectqry).fetchone()

    if db_list is None or len(db_list) == 0:
        return {"resp": {"error": {"code": "InvalidID",
                                   "message": "Not a valid MSSQL ID (OR) ID removed."}
                         }, "status_code": 400}
    else:
        conn_url = sa.engine.URL.create(
            "mssql+pyodbc",
            username=db_list.dbc_username,
            password=db_list.dbc_password,
            host=db_list.dbc_server_host,
            database=db_list.dbc_name,
            query={
                "driver": "ODBC Driver 17 for SQL Server",
                "autocommit": "True",
            },
        )

        file_name = uuid.uuid4().hex
        block_blob_service = BlockBlobService(acc_name, token)
        block_blob_service.get_blob_to_path(container_name, blob_name, file_name)
        conn_engine = create_engine(conn_url).execution_options(isolation_level="AUTOCOMMIT")
        conn_engine.execute(
            "IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = '" + schema_name + "') BEGIN EXEC('CREATE SCHEMA " + schema_name + "') END")
        excel_files = pd.ExcelFile(file_name)
        sheet_names = excel_files.sheet_names if sheet_indices.strip() == '' else [item for index, item in
                                                                                   enumerate(excel_files.sheet_names) if
                                                                                   index in [int(i) for i in
                                                                                             sheet_indices.split(',')]]

        for sheet in sheet_names:
            sheet_name = sheet
            df = pd.read_excel(excel_files, sheet)
            df.to_sql(sheet_name, con=conn_engine, schema=schema_name)

        return {"resp": {"message": "BLOB Uploaded in MSSQL"}, "status_code": 200}


# Connecting to Tally
def connect_to_tally(tally_host_address, tally_port_number, tally_company_name, tally_from_date, tally_to_date,
                     tally_masters_list, user_email):
    xml = """
      <ENVELOPE>
          <HEADER>
              <VERSION>1</VERSION>
              <TALLYREQUEST>Export</TALLYREQUEST>
              <TYPE>Data</TYPE>
              <ID>List Of Ledger</ID>
          </HEADER>
          <BODY>
              <DESC>
                  <STATICVARIABLES>
                      <SVEXPORTFORMAT>$$SysName:XML</SVEXPORTFORMAT>
                      <SVCURRENTCOMPANY>""" + tally_company_name + """</SVCURRENTCOMPANY>
                      <SVFROMDATE TYPE="Date">""" + tally_from_date + """</SVFROMDATE>
                      <SVTODATE TYPE="Date">""" + tally_to_date + """</SVTODATE>
                  </STATICVARIABLES>
                  <TDL>
                      <TDLMESSAGE>
                          <REPORT ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="List Of Ledger">
                              <FORMS>List Of Ledger</FORMS>
                          </REPORT>
                          <FORM ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="List Of Ledger">
                              <TOPPARTS>List Of Ledger</TOPPARTS>
                              <XMLTAG>ListOfLedger</XMLTAG>
                          </FORM>
                          <PART ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="List Of Ledger">
                              <TOPLINES>List Of Ledger</TOPLINES>
                              <REPEAT>List Of Ledger : FormList Of Ledger</REPEAT>
                              <SCROLLED>Vertical</SCROLLED>
                          </PART>
                          <LINE ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="List Of Ledger">
                              <LEFTFIELDS>MASTERID</LEFTFIELDS>
                          </LINE>
                          <FIELD ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="MASTERID">
                              <SET>$GUID</SET>
                              <XMLTAG>GUID</XMLTAG>
                          </FIELD>
                          <FIELD ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="VoucherNumber">
                              <SET>$VoucherNumber</SET>
                              <XMLTAG>VoucherNumber</XMLTAG>
                          </FIELD>
                          <FIELD ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="Date">
                              <SET>$Date</SET>
                              <XMLTAG>Date</XMLTAG>
                          </FIELD>
                          <COLLECTION ISMODIFY="No" ISFIXED="No" ISINITIALIZE="No" ISOPTION="No" ISINTERNAL="No" NAME="FormList Of Ledger">
                              <TYPE>Groups</TYPE>
                          </COLLECTION>
                      </TDLMESSAGE>
                  </TDL>
              </DESC>
          </BODY>
      </ENVELOPE>"""

    headers = {'Content-Type': 'application/xml'}  # set what your server accepts
    try:
        xmlResult = requests.post(tally_host_address + ':' + tally_port_number, data=xml, headers=headers).text.replace(
            "&#10;", "").replace("&#13;", "").replace("&#4;", "").replace("'", "''")

        data_dict = xmltodict.parse(xmlResult)
        voucher = data_dict['LISTOFLEDGER']['GUID']
        json_data = json.dumps(voucher, sort_keys=True, indent=4, separators=(',', ': '))
        jsonData = json.loads(json_data)

        engine = create_engine(connection_url).execution_options(
            isolation_level="AUTOCOMMIT"
        )

        selectqry = """SELECT * FROM tally_config WHERE tc_created_by = '""" + user_email + """'
                AND tc_company_name = '""" + tally_company_name + """' 
                AND tc_start_date = '""" + tally_from_date + """'
                AND tc_end_date = '""" + tally_to_date + """' 
                AND tc_host_address = '""" + tally_host_address + """' 
                AND tc_port_number = '""" + tally_port_number + """'"""
        table_list = engine.execute(selectqry).fetchall()
        if len(table_list) == 0:
            insqry = """INSERT INTO tally_config (tc_company_name, tc_start_date, tc_end_date, tc_master_list, tc_host_address, tc_port_number, tc_created_by )
      VALUES ('""" + tally_company_name + """', '""" + tally_from_date + """', '""" + tally_to_date + """', '""" + tally_masters_list + """', 
      '""" + tally_host_address + """', '""" + tally_port_number + """', '""" + user_email + """')"""
            engine.execute(insqry)

        return {"resp": {"message": "Tally Config Saved Successfully"}, "status_code": 200}
    except:
        return {"resp": {"error": {"code": "InvalidDetails",
                                   "message": "Not valid Input (OR) Tally is Not running"}
                         }, "status_code": 400}


@api_view(['POST'])
def get_session_token(request):
    token = request.POST.get('access_token', '')
    refresh_token = request.POST.get('refresh_token', '')
    if token == "":
        err_resp = {"error": {"code": "invalid_request",
                              "message": "The request body must contain the following parameter: 'access_token'."}}
        return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
    elif refresh_token == "":
        err_resp = {"error": {"code": "invalid_request",
                              "message": "The request body must contain the following parameter: 'refresh_token'."}}
        return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
    else:
        user_detail_resp = get_user_details_from_graph(token)
        user_status_code = user_detail_resp.status_code
        user_detail_resp_json = user_detail_resp.json()
        if user_status_code != 200:
            err_resp = {"error": {"code": "InvalidAuthenticationToken",
                                  "message": "Invalid request. 'access_token' is invalid"}}
            return Response(err_resp, status=user_status_code)
        else:
            azure_auth_resp = get_azure_subscription_details_from_rest_api(refresh_token)
            az_status_code = azure_auth_resp.status_code
            azure_auth_resp_json = azure_auth_resp.json()
            if az_status_code != 200:
                err_resp = {"error": {"code": "InvalidAuthenticationToken",
                                      "message": "Invalid request. 'refresh_token' is invalid"}}
                return Response(err_resp, status=az_status_code)
            else:
                auth_key = get_auth_key(token, refresh_token, user_detail_resp_json['mail'])
                if auth_key['status_code'] == 200:
                    session_resp = {"is_authenticated": True, "auth_key": auth_key['session_key']}
                    # return session ID
                    return Response(session_resp, status=200)
                else:
                    session_resp = {"is_authenticated": False,
                                    "error": {"code": "AuthenticationFailed", "message": "Authentication Failed"}
                                    }
                    # return session ID
                    return Response(session_resp, status=auth_key['status_code'])


@api_view(['GET'])
def get_user(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        return Response(auth_response['response']['user_details'])


@api_view(['GET'])
def subscription_list(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        azure_token = auth_response['response']['azsl_refresh_token']
        # Set headers
        headers = {'Authorization': 'Bearer {0}'.format(azure_token)}
        subscriptionList = requests.get('https://management.azure.com/subscriptions?api-version=2020-01-01',
                                        headers=headers)
        subscription_list_json = subscriptionList.json()
        if subscription_list_json:
            subscription_list_json_values = subscription_list_json['value']
            for subs in subscription_list_json_values:
                save_subscription_list(subs)

        # Return the JSON result
        return Response(subscription_list_json)


@api_view(['GET'])
def storage_account_list(request):
    auth_key = request.GET.get('auth_key', '')
    subscription_id = request.GET.get('subscription_id', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        if subscription_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'subscription_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            azure_token = auth_response['response']['azsl_refresh_token']
            # Set headers
            headers = {'Authorization': 'Bearer {0}'.format(azure_token)}

            res_storage_account_list = requests.get(
                'https://management.azure.com{0}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01'
                    .format(subscription_id), headers=headers)

            storage_account_list_json = res_storage_account_list.json()
            storage_account_list_status_code = res_storage_account_list.status_code

            if storage_account_list_status_code != 200:
                return Response(storage_account_list_json, status=storage_account_list_status_code)
            else:
                if storage_account_list_json:
                    storage_account_list_json_values = storage_account_list_json['value']
                    subs_id = subscription_id.replace("/subscriptions/", "")
                    tenant_id = get_tenant_id_from_subscription_id(subs_id)
                    for storage in storage_account_list_json_values:
                        save_storage_list(subs_id, tenant_id, storage)

                # Return the JSON result
                return Response(storage_account_list_json)


@api_view(['GET'])
def container_list(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        storage_id = request.GET.get('storage_id', '')
        if storage_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'storage_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            azure_token = auth_response['response']['azsl_refresh_token']
            # Set headers
            headers = {'Authorization': 'Bearer {0}'.format(azure_token)}
            blob_list = requests.get(
                'https://management.azure.com{0}/blobServices/default/containers?api-version=2021-04-01'.format(
                    storage_id),
                headers=headers)
            return Response(blob_list.json(), status=blob_list.status_code)


@api_view(['GET'])
def blob_details(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        container_id = request.GET.get('container_id', '')
        if container_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'container_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            container_name = container_id.rsplit('/', 1)[-1]
            storage_id = container_id.rsplit('/blobServices/default/containers', 1)[0]
            blob_access_key = get_blob_access_key(storage_id)
            if blob_access_key is None:
                return {"resp": {"error": {"code": "ContainerIDNotValid", "message": "CONTAINER ID is Not Valid"}},
                        "status_code": 400}
            else:
                storage_access_key = blob_access_key.storage_access_key
                storage_account_name = storage_id.rsplit('/', 1)[-1]
                if storage_access_key is None:
                    err_resp = {"error": {"code": "StorageKeyNotFound",
                                          "message": "Storage Account Access token is missing."}}
                    return Response(err_resp, status=404)
                else:
                    server = BlockBlobService(storage_account_name, storage_access_key)
                    result = server.list_blobs(container_name, include="Metadata")
                    blobs = []
                    for res in result:
                        blob_owner = blob_status = blob_assignee = blob_category = ""
                        if res.metadata:
                            if 'owner' in res.metadata.keys():
                                blob_owner = res.metadata['owner']
                            if 'status' in res.metadata.keys():
                                blob_status = res.metadata['status']
                            if 'assignee' in res.metadata.keys():
                                blob_assignee = res.metadata['assignee']
                            if 'category' in res.metadata.keys():
                                blob_category = res.metadata['category']
                        bl_arr = {
                            "name": res.name,
                            "blob_type": res.properties.blob_type,
                            "last_modified": res.properties.last_modified.strftime("%d/%b/%Y, %H:%M:%S"),
                            "content_length": res.properties.content_length,
                            "download_link": "https://" + storage_account_name + ".blob.core.windows.net/" + container_name + "/" + res.name,
                            "owner": blob_owner,
                            "status": blob_status,
                            "assignee": blob_assignee,
                            "category": blob_category
                        }
                        blobs.append(bl_arr)
                    result_list = {"values": blobs, "count": {"type": "total", "value": len(blobs)}}
                    return Response(result_list)


@api_view(['GET'])
def workflow_details(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        storage_id = request.GET.get('storage_id', '')
        if storage_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'storage_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            azure_token = auth_response['response']['azsl_refresh_token']
            # Set headers
            headers = {'Authorization': 'Bearer {0}'.format(azure_token)}
            container_list_of_storage = requests.get(
                'https://management.azure.com{0}/blobServices/default/containers?api-version=2021-04-01'.format(
                    storage_id),
                headers=headers)
            if container_list_of_storage.status_code != 200:
                return Response(container_list_of_storage.json(), status=container_list_of_storage.status_code)
            else:
                container_name = 'workflow'
                blob_access_key = get_blob_access_key(storage_id)
                if blob_access_key is None:
                    return {"resp": {"error": {"code": "ContainerNotFound", "message": "Workflow container is missing"}},
                            "status_code": 404}
                else:
                    storage_access_key = blob_access_key.storage_access_key
                    storage_account_name = storage_id.rsplit('/', 1)[-1]
                    if storage_access_key is None:
                        err_resp = {"error": {"code": "StorageKeyNotFound",
                                              "message": "Storage Account Access token is missing."}}
                        return Response(err_resp, status=404)
                    else:
                        server = BlockBlobService(storage_account_name, storage_access_key)
                        result = server.list_blobs(container_name, include="Metadata")
                        blobs = []
                        for res in result:
                            blob_owner = blob_status = blob_assignee = blob_category = ""
                            if res.metadata:
                                if 'owner' in res.metadata.keys():
                                    blob_owner = res.metadata['owner']
                                if 'status' in res.metadata.keys():
                                    blob_status = res.metadata['status']
                                if 'assignee' in res.metadata.keys():
                                    blob_assignee = res.metadata['assignee']
                                if 'category' in res.metadata.keys():
                                    blob_category = res.metadata['category']
                            bl_arr = {
                                "name": res.name,
                                "blob_type": res.properties.blob_type,
                                "last_modified": res.properties.last_modified.strftime("%d/%b/%Y, %H:%M:%S"),
                                "content_length": res.properties.content_length,
                                "download_link": "https://" + storage_account_name + ".blob.core.windows.net/" + container_name + "/" + res.name,
                                "owner": blob_owner,
                                "status": blob_status,
                                "assignee": blob_assignee,
                                "category": blob_category
                            }
                            blobs.append(bl_arr)
                        result_list = {"values": blobs, "count": {"type": "total", "value": len(blobs)}}
                        return Response(result_list)


@api_view(['GET'])
def dbconfig_folder_details(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        storage_id = request.GET.get('storage_id', '')
        if storage_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'storage_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            azure_token = auth_response['response']['azsl_refresh_token']
            # Set headers
            headers = {'Authorization': 'Bearer {0}'.format(azure_token)}
            container_list_of_storage = requests.get(
                'https://management.azure.com{0}/blobServices/default/containers?api-version=2021-04-01'.format(
                    storage_id),
                headers=headers)
            if container_list_of_storage.status_code != 200:
                return Response(container_list_of_storage.json(), status=container_list_of_storage.status_code)
            else:
                container_name = 'configuration'
                blob_access_key = get_blob_access_key(storage_id)
                if blob_access_key is None:
                    return {"resp": {"error": {"code": "ContainerNotFound", "message": "Workflow container is missing"}},
                            "status_code": 404}
                else:
                    storage_access_key = blob_access_key.storage_access_key
                    storage_account_name = storage_id.rsplit('/', 1)[-1]
                    if storage_access_key is None:
                        err_resp = {"error": {"code": "StorageKeyNotFound",
                                              "message": "Storage Account Access token is missing."}}
                        return Response(err_resp, status=404)
                    else:
                        server = BlockBlobService(storage_account_name, storage_access_key)
                        result = server.list_blobs(container_name, include="Metadata")
                        blobs = []
                        for res in result:
                            blob_owner = blob_status = blob_assignee = blob_category = ""
                            if res.metadata:
                                if 'owner' in res.metadata.keys():
                                    blob_owner = res.metadata['owner']
                                if 'status' in res.metadata.keys():
                                    blob_status = res.metadata['status']
                                if 'assignee' in res.metadata.keys():
                                    blob_assignee = res.metadata['assignee']
                                if 'category' in res.metadata.keys():
                                    blob_category = res.metadata['category']
                            bl_arr = {
                                "name": res.name,
                                "blob_type": res.properties.blob_type,
                                "last_modified": res.properties.last_modified.strftime("%d/%b/%Y, %H:%M:%S"),
                                "content_length": res.properties.content_length,
                                "download_link": "https://" + storage_account_name + ".blob.core.windows.net/" + container_name + "/" + res.name,
                                "owner": blob_owner,
                                "status": blob_status,
                                "assignee": blob_assignee,
                                "category": blob_category
                            }
                            blobs.append(bl_arr)
                        result_list = {"values": blobs, "count": {"type": "total", "value": len(blobs)}}
                        return Response(result_list)


@api_view(['GET'])
def folders_details(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        storage_id = request.GET.get('storage_id', '')
        if storage_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'storage_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            azure_token = auth_response['response']['azsl_refresh_token']
            # Set headers
            headers = {'Authorization': 'Bearer {0}'.format(azure_token)}
            container_list_of_storage = requests.get(
                'https://management.azure.com{0}/blobServices/default/containers?api-version=2021-04-01'.format(
                    storage_id),
                headers=headers)
            if container_list_of_storage.status_code != 200:
                return Response(container_list_of_storage.json(), status=container_list_of_storage.status_code)
            else:
                container_name = 'configuration'
                blob_access_key = get_blob_access_key(storage_id)
                if blob_access_key is None:
                    return {"resp": {"error": {"code": "ContainerNotFound", "message": "Workflow container is missing"}},
                            "status_code": 404}
                else:
                    storage_access_key = blob_access_key.storage_access_key
                    storage_account_name = storage_id.rsplit('/', 1)[-1]
                    if storage_access_key is None:
                        err_resp = {"error": {"code": "StorageKeyNotFound",
                                              "message": "Storage Account Access token is missing."}}
                        return Response(err_resp, status=404)
                    else:
                        server = BlockBlobService(storage_account_name, storage_access_key)
                        result = server.list_blobs(container_name, include="Metadata")
                        blobs = []
                        for res in result:
                            blob_owner = blob_status = blob_assignee = blob_category = ""
                            if res.metadata:
                                if 'owner' in res.metadata.keys():
                                    blob_owner = res.metadata['owner']
                                if 'status' in res.metadata.keys():
                                    blob_status = res.metadata['status']
                                if 'assignee' in res.metadata.keys():
                                    blob_assignee = res.metadata['assignee']
                                if 'category' in res.metadata.keys():
                                    blob_category = res.metadata['category']
                            bl_arr = {
                                "name": res.name,
                                "blob_type": res.properties.blob_type,
                                "last_modified": res.properties.last_modified.strftime("%d/%b/%Y, %H:%M:%S"),
                                "content_length": res.properties.content_length,
                                "download_link": "https://" + storage_account_name + ".blob.core.windows.net/" + container_name + "/" + res.name,
                                "owner": blob_owner,
                                "status": blob_status,
                                "assignee": blob_assignee,
                                "category": blob_category
                            }
                            blobs.append(bl_arr)
                        result_list = {"values": blobs, "count": {"type": "total", "value": len(blobs)}}
                        return Response(result_list)


@api_view(['POST'])
def upload_blob(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        container_id = request.POST.get('container_id', '')
        assignee_name = request.POST.get('assignee_name', '')
        category = request.POST.get('category', '')
        bl_status = request.POST.get('status', '')
        folder_name = request.POST.get('folder_name', '')

        if container_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'container_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif assignee_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'assignee_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif category == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'category'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif bl_status == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'status'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            container_name = container_id.rsplit('/', 1)[-1]
            storage_id = container_id.rsplit('/blobServices/default/containers', 1)[0]
            blob_access_key = get_blob_access_key(storage_id)
            if blob_access_key is None:
                return {"resp": {"error": {"code": "ContainerIDNotValid", "message": "CONTAINER ID is Not Valid"}},
                        "status_code": 400}
            else:
                storage_access_key = blob_access_key.storage_access_key
                storage_account_name = storage_id.rsplit('/', 1)[-1]
                if storage_access_key is None:
                    err_resp = {"error": {"code": "StorageKeyNotFound",
                                          "message": "Storage Account Access token is missing."}}
                    return Response(err_resp, status=404)
                else:
                    if 'myfile' in request.FILES:
                        myfile = request.FILES['myfile']
                        block_blob_service = BlockBlobService(storage_account_name, storage_access_key)
                        user_email = auth_response['response']['user_details']['mail']
                        custom_params_blob = {"owner": user_email, "assignee": assignee_name,
                                              "status": bl_status, "category": category}
                        if folder_name != "":
                            blob_name_to_upload = folder_name+'/'+myfile.name
                        else:
                            blob_name_to_upload = myfile.name

                        block_blob_service.create_blob_from_bytes(container_name, blob_name_to_upload, myfile.read(),
                                                                  metadata= custom_params_blob)
                        file_resp = {"message": "File Uploaded Successfully."}
                        return Response(file_resp)
                    else:
                        err_resp = {"error": {"code": "FileNotFound",
                                              "message": "File Not Found."}}
                        return Response(err_resp, status=404)


@api_view(['POST'])
def storage_key(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        storage_id = request.POST.get('storage_id', '')
        blob_access_key = request.POST.get('blob_access_key', '')

        if storage_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'storage_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif blob_access_key == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'blob_access_key'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            result_resp = save_blob_access_key(storage_id, blob_access_key)
            return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['GET'])
def db_list(request):
    # if 'Authorization' not in request.headers:
    #     err_resp = {"is_authenticated": False,
    #                 "response":
    #                     {"error":
    #                          {"code": "invalid_request",
    #                           "message": "'Authorization' is Missing in Headers."
    #                           }
    #                      }}
    #     return Response(err_resp, 400)
    # else:
    #     auth_key = request.headers['Authorization']
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        engine = create_engine(connection_url).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        user_email = auth_response['response']['user_details']['mail']
        table_list = engine.execute("select * from db_config WHERE dbc_created_by = '" + user_email + "'").fetchall()
        return Response(table_list)


@api_view(['POST'])
def add_to_db_list(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        dbc_server_unq_name = request.POST.get('db_connection_name', '')
        db_server_host = request.POST.get('db_server_host', '')
        db_username = request.POST.get('db_username', '')
        db_password = request.POST.get('db_password', '')
        db_port = request.POST.get('db_port', '')
        db_name = request.POST.get('db_name', '')
        db_type = request.POST.get('db_type', '')
        user_email = auth_response['response']['user_details']['mail']

        if db_server_host == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_server_host'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif dbc_server_unq_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_connection_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_username == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_username'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_type == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_type'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)

        # check and add in DB
        result_resp = store_db_connection_in_db(dbc_server_unq_name, db_server_host, db_username, db_password, db_port,
                                                db_name, db_type, user_email)

        return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['POST'])
def update_db_list(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        id = request.POST.get('id', '')
        dbc_server_unq_name = request.POST.get('db_connection_name', '')
        db_server_host = request.POST.get('db_server_host', '')
        db_username = request.POST.get('db_username', '')
        db_password = request.POST.get('db_password', '')
        db_port = request.POST.get('db_port', '')
        db_name = request.POST.get('db_name', '')
        db_type = request.POST.get('db_type', '')
        user_email = auth_response['response']['user_details']['mail']

        if id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_server_host == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_server_host'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif dbc_server_unq_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_connection_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_username == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_username'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif db_type == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_type'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)

        # check and add in DB
        result_resp = update_db_connection_in_db(id, dbc_server_unq_name, db_server_host, db_username, db_password, db_port,
                                                db_name, db_type, user_email)

        return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['POST'])
def connect_to_db_list(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        dbc_id = request.POST.get('id', '')
        user_email = auth_response['response']['user_details']['mail']
        if dbc_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            result_resp = check_db_connection_by_id(dbc_id, user_email)
            return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['POST'])
def get_data_from_tbl(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        dbc_id = request.POST.get('id', '')
        schema = request.POST.get('schema', '')
        tbl_name = request.POST.get('tbl_name', '')
        if dbc_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif schema == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'schema'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif tbl_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'tbl_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            user_email = auth_response['response']['user_details']['mail']
            result_resp = get_table_records(dbc_id, schema, tbl_name, user_email)
            return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['POST'])
def add_column_tbl(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)
    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        dbc_id = request.POST.get('id', '')
        schema = request.POST.get('schema', '')
        tbl_name = request.POST.get('tbl_name', '')
        if dbc_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif schema == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'schema'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif tbl_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'tbl_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            result_resp = get_table_records(dbc_id, schema, tbl_name)
            return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['POST'])
def move_blob_to_sql(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        dbc_id = request.POST.get('db_detail_id', '')
        container_id = request.POST.get('container_id', '')
        blob_name = request.POST.get('blob_name', '')
        schema_name = request.POST.get('schema_name', '')
        sheet_numbers = request.POST.get('sheet_numbers', '')
        if dbc_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'db_detail_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif container_id == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'container_id'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif blob_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'blob_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif schema_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'schema_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            container_name = container_id.rsplit('/', 1)[-1]
            storage_id = container_id.rsplit('/blobServices/default/containers', 1)[0]
            blob_access_key = get_blob_access_key(storage_id)
            if blob_access_key is None:
                return {"resp": {"error": {"code": "ContainerIDNotValid", "message": "CONTAINER ID is Not Valid"}},
                        "status_code": 400}
            else:
                storage_access_key = blob_access_key.storage_access_key
                storage_account_name = storage_id.rsplit('/', 1)[-1]
                if storage_access_key is None:
                    err_resp = {"error": {"code": "StorageKeyNotFound",
                                          "message": "Storage Account Access token is missing."}}
                    return Response(err_resp, status=404)
                else:
                    result_resp = move_to_msql(dbc_id, storage_access_key, storage_account_name, container_name,
                                               blob_name,
                                               schema_name, sheet_numbers)
                    return Response(result_resp['resp'], status=result_resp['status_code'])


@api_view(['GET'])
def tally_connection_list(request):
    auth_key = request.GET.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        engine = create_engine(connection_url).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        user_email = auth_response['response']['user_details']['mail']
        table_list = engine.execute(
            "select *, CASE WHEN tc_is_completed = '1' THEN 'Completed' WHEN tc_is_completed = '0' THEN 'Not Started' WHEN tc_is_completed = '2' THEN 'Running' END AS job_status from tally_config WHERE tc_created_by = '" + user_email + "'").fetchall()
        return Response(table_list)


@api_view(['POST'])
def add_tally_connection(request):
    auth_key = request.POST.get('auth_key', '')
    auth_response = check_user_authentication(auth_key)

    if not auth_response['is_authenticated']:
        return Response(auth_response['response'], status=auth_response['status_code'])
    else:
        company_name = request.POST.get('company_name', '')
        from_date = request.POST.get('from_date', '')
        to_date = request.POST.get('to_date', '')
        masters_list = request.POST.get('masters_list', '')
        host_address = request.POST.get('host_address', '')
        port_number = request.POST.get('port_number', '')

        if company_name == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'company_name'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif from_date == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'from_date'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif to_date == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'to_date'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif masters_list == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'masters_list'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif host_address == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'host_address'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        elif port_number == "":
            err_resp = {"error": {"code": "invalid_request",
                                  "message": "The request body must contain the following parameter: 'port_number'."}}
            return Response(err_resp, status=status.HTTP_400_BAD_REQUEST)
        else:
            user_email = auth_response['response']['user_details']['mail']
            result_resp = connect_to_tally(host_address, port_number, company_name, from_date, to_date, masters_list,
                                          user_email)
            return Response(result_resp['resp'], status=result_resp['status_code'])


# refreshing SSAS Cubes
def refresh_ssas(request):
    tenant_id = '05f00303-5336-44d6-863e-165186fcbdef'
    authentication_endpoint = f'https://login.windows.net/{tenant_id}'
    resource = 'https://japaneast.asazure.windows.net/'
    client_id = 'da2d8409-9e4f-437e-a0f2-2171be2736cf'
    client_secret = 'ZIR8Q~ORKWYG7C1jrctKBAxj3PIIgb5qE15pFdv6'
    # get an Azure access token using the adal library
    context = adal.AuthenticationContext(authentication_endpoint)
    token_response = context.acquire_token_with_client_credentials(resource, client_id, client_secret)

    access_token = token_response.get('accessToken')

    location = 'japaneast'
    server_name = 'devssas'
    model = 'dwinsight_demo_1_VIKAS_0767ce70-ba15-45dd-a370-0e97a0b1f074'

    url = f'https://{location}.asazure.windows.net/servers/{server_name}/models/{model}/refreshes'
    data = dict(type='Full')

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.post(url=url, headers=headers, data=json.dumps(data))
    # response = requests.get(url=url, headers=headers)
    res = json.loads(response.text)
    if response.status_code == 202:
        op_id = res['operationId']
        chk_status = True
        status_code = 0
        resp_msg_status = ""
        sp_time = 0
        while chk_status:
            if status_code != 200:
                read_res = requests.get(url=url+'/'+op_id, headers=headers)
                # check the status code and assign to status_code
                status_code = read_res.status_code
                resp_msg_txt = read_res.text
                resp_msg = json.loads(read_res.text)
                resp_msg_status = resp_msg['status']
                print("Status code is not 200, entering sleep for 5 seconds")
                time.sleep(5)
                sp_time = sp_time+5
            elif resp_msg_status != "succeeded":
                read_res = requests.get(url=url+'/'+op_id, headers=headers)
                status_code = read_res.status_code
                resp_msg_txt = read_res.text
                resp_msg = json.loads(read_res.text)
                resp_msg_status = resp_msg['status']
                # check the the status and assign to offense_response.status_code
                if resp_msg_status != "succeeded":
                    print("Status is '" + resp_msg_status + "', entering sleep for 5 seconds")
                    time.sleep(5)
                    sp_time = sp_time + 5
                else:
                    print("Status is '" + resp_msg_status + "'")
            else:
                print("status code is 200, hence exiting, slept for '"+str(sp_time)+"' seconds")
                chk_status = False
    else:
        read_res = requests.get(url=url, headers=headers)
        resp_msg_txt = read_res.text

    return HttpResponse(resp_msg_txt)