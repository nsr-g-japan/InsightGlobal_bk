from django.urls import path
from .views import *

urlpatterns = [
    path('subscription_list', subscription_list),
    path('storage_account_list', storage_account_list),
    path('container_list', container_list),
    path('blob_details', blob_details),
    path('workflow_details', workflow_details),
    path('dbconfig_details', dbconfig_folder_details),
    path('workflow_folders', folders_details),
    path('storage_key', storage_key),
    path('user_details', get_user),
    path('get_session_token', get_session_token),
    path('upload_blob', upload_blob),
    path('db_list', db_list),
    path('add_to_db_list', add_to_db_list),
    path('update_db_list', update_db_list),
    path('get_table_list', connect_to_db_list),
    path('get_data_from_tbl', get_data_from_tbl),
    path('add_column_tbl', add_column_tbl),
    path('move_blob_to_sql', move_blob_to_sql),
    path('get_tally_connections', tally_connection_list),
    path('add_tally_connection', add_tally_connection),
    path('refresh_ssas', refresh_ssas),
    path('getPbiEmbedToken', getPbiEmbedToken)

]
