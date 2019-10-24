<?php

/**
 * This file contain Web services methods for native app (iOS and Android)
 * @name       WebServicesController.php
 * @class      WebServicesController
 * @date       19 Jan 2014
 * @author     Rahul Lahariya
 */
App::uses('RestController', 'Controller');
App::import('Controller', 'Auditors');
App::import('Controller', 'Users');
App::uses('Security', 'Utility');
App::uses('Sanitize', 'Utility');
App::import('Controller', 'Managements');

//Configure::write('debug',0);
class WebServicesController extends RestController {

    public $components = array('Paginator','RestAuth','Encryption', 'Users', 'Email', 'File', 'Validates', 'Audits', 'UtilityFunction');
    public $helpers = array('User');
    protected $_content_type = "application/json";
    protected $_extension = 'json'; // json is default format. Other supported format is xml
    protected $_code = 200;
    protected $_user = array();
    private $loginUserId = '';
    private $_token = '';
    private $logFileId = '';  


    public function beforeFilter() {
        parent::beforeFilter();
        //Allow Function //

        $this->layout = false;
        $this->autoRender = false;

        $allHeaders = getallheaders();
        $contact['url'] = $this->params['action'];
        $contact['headers'] = json_encode($allHeaders);
        $contact['requestdata'] = json_encode($this->params['data']);
        $contact['created'] = date("Y-m-d");
        $this->loadModel('LogWebservices');
        $result = $this->LogWebservices->save($contact);
        $this->logFileId = $this->LogWebservices->getLastInsertId();

        // Get current login user data for use array ($this->_user) any function of web services controller
        $this->RestAuth->allow(array('getLeaveDays','leaveRequest','getNotifications','getAuditorNotifications','getSubadminIdByAuditorId','requestForPayment','getGapAnalysis','deleteAudit','getActionChecklist','auditPushNotification','addSummary','getAuditReport','getSummary','updateAudit','getDefaultResponses','auditGroupListing','runAudit','auditGroupQuestion','groupListing','getCertificate','getAuditWorkSheetPDF','saveNotification','printCertificate','auditListing','createAudit','subOfficesListingApi','getAuditDate','subOfficesCreateAuditApi','subOfficesAuditListingApi','auditListing','getClientDetail','getAllClients','recursiveOptionFieldsFrontEnd','locationListing','changePassword','signUp','privacyPolicy', 'contactUs', 'aboutUs','login', 'resetPassword', 'signOut'));
        $this->_user_id = isset($_SERVER['PHP_AUTH_USER']) ? (trim($_SERVER['PHP_AUTH_USER'])) : '';
        $this->_token = isset($_SERVER['PHP_AUTH_PW']) ? trim($_SERVER['PHP_AUTH_PW']) : '';     //current request token
        //assigns current user row data
        $this->loadModel('User');
        $this->loadModel('Audit');
        $this->_user = $this->User->find('first', array('conditions' =>
            array('User.email' => $this->_get_username(),
                'User._token' => $this->_get_password()),
            'fields' => array('User.*')));        

        if(!empty($allHeaders['Authorization']) && !empty($allHeaders['email'])){
            $this->loadModel('User');
            $this->loadModel('Audit');
            $user = $this->User->find('first', array('conditions' =>
                array('User.email' => Sanitize::escape($allHeaders['email']),'User._token' => Sanitize::escape($allHeaders['Authorization'])),
                'fields' => array('User.*')));                
            if(count($user) > 0 ){
                $this->loginUserId = $user['User']['id'];
                $this->RestAuth->allow(array('getSummary','subOfficesListingApi','subOfficesCreateAuditApi','subOfficesAuditListingApi','addAuditorQuestion','sendBarChartTOEmail','getGapAnalysis','getAuditReport','getAuditWorkSheetPDF','changePassword','addSummary', 'getCertificate', 'auditWorkSheetPDF', 'barChartPdf', 'updateExtraGroupInfo', 'auditGroupExtraInfo', 'signUp', 'deleteAudit', 'getActionChecklist', 'getAuditDate', 'privacyPolicy', 'contactUs', 'aboutUs', 'deleteQuestion', 'reportsClient', 'updateQuestion', 'createAudit', 'login', 'resetPassword', 'signOut', 'updateAuditerInfo', 'auditListing', 'questionListing', 'groupListing', 'addQuestion', 'updateAudi-t', 'addGroup', 'saveAudit', 'auditGroupListing', 'groupQuestion', 'auditGroupQuestion', 'getNotifications', 'deleteNotifications', 'getAllClients', 'runAudit', 'getClientDetail', 'changeQuestionOnFly', 'updateGroup', 'reportListing', 'reportsClientDetail', 'testpdf', 'demo_pdf', 'deleteGroup', 'reportlistingpdf', 'reportclientpdf', 'reportclientpdf_link', 'actionChecklistpdf', 'updateActionChecklist','printCertificate','markAuditComplete','savecontact','getDefaultResponses', 'getDefaultResponsesAutofill','test'));
            }else{
                $this->RestAuth->allow(array('changePassword','signUp','privacyPolicy', 'contactUs', 'aboutUs','login', 'resetPassword', 'signOut'));
            }
        }else{
            $this->RestAuth->allow(array('changePassword','signUp','privacyPolicy', 'contactUs', 'aboutUs','login', 'resetPassword', 'signOut'));
        }

    }


    private function saveLogBeforeRetruning($data){

        $contact['id'] = $this->logFileId;
        $contact['output'] = json_encode($data);
        $this->loadModel('LogWebservices');
        $ContactArr = $this->LogWebservices->save($contact);

    }



    protected function _get_username() {
        return $this->_user_id;
    }

    protected function _get_password() {
        return $this->_token;
    }

    protected function _get_status_message() {
        $status = array(
            100 => 'Continue', 101 => 'Switching Protocols', 200 => 'OK', 201 => 'Created', 202 => 'Accepted', 203 => 'Non-Authoritative Information',
            204 => 'No Content', 205 => 'Reset Content', 206 => 'Partial Content', 300 => 'Multiple Choices', 301 => 'Moved Permanently',
            302 => 'Found', 303 => 'See Other', 304 => 'Not Modified', 305 => 'Use Proxy', 306 => '(Unused)', 307 => 'Temporary Redirect',
            400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed',
            406 => 'Not Acceptable', 407 => 'Proxy Authentication Required', 408 => 'Request Timeout', 409 => 'Conflict', 410 => 'Gone',
            411 => 'Length Required', 412 => 'Precondition Failed', 413 => 'Request Entity Too Large', 414 => 'Request-URI Too Long',
            415 => 'Unsupported Media Type', 416 => 'Requested Range Not Satisfiable', 417 => 'Expectation Failed', 500 => 'Internal Server Error',
            501 => 'Not Implemented', 502 => 'Bad Gateway', 503 => 'Service Unavailable', 504 => 'Gateway Timeout', 505 => 'HTTP Version Not Supported');
        return ($status[$this->_code]) ? $status[$this->_code] : $status[500];
    }

    protected function _set_headers() {
        header("HTTP/1.1 " . $this->_code . " " . $this->_get_status_message());
        header("Content-Type:" . $this->_content_type);
    }

    protected function _get_headers() {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (count($headers)) {
                foreach ($headers as $name => $value) {
                    $this->_headers[$name] = $value;
                }
            }
        }
    }

    public function savecontact(){
        $name = $_POST["name"];
        $email = $_POST["email"];
        $msg = $_POST["message"];
        $contact = array();
        $contact['name'] = $name;
        $contact['email'] = $email;
        $contact['message'] = $msg;
        $this->loadModel('Contact');
        $ContactArr = $this->Contact->save($contact);
        if(!empty($ContactArr)){
            $senderEmail = DEFAULT_EMAIL_ADDRESS;
            $message = "Enquiry report <br><br>";
            $message.= '<table border="0">
            <tbody>
                <tr><td>Name:</td><td>' .$name . '</td></tr>
                <tr><td>Email: </td><td>' . $email . '</td></tr>
                <tr><td>Message: </td><td>' . $msg . '</td></tr>
            </tbody>
        </table>';
        $subject = "Contact Details";
        if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message)) {
            $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
        }
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Please try again!');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function _get_error_code($code = 'ERROR') {
        $status = array(
            'ERROR' => 'E_10001',
            'VALIDATION_ERROR' => 'E_10003',
            'INVALID_DATA_ERROR' => 'E_10004',
            'SERVER_ERROR' => 'E_10005',
            'INACTIVE_ACCOUNT_ERROR' => 'E_10007',
            'SUSPENDED_ACCOUNT_ERROR' => 'E_10009',
            'INVALID_ACCOUNT_ERROR' => 'E_10011',
            'INVALID_EMAIL_ERROR' => 'E_10013',
            'INVALID_PASSWORD_ERROR' => 'E_10015',
            'INVALID_GCM_REGISTRATION_ID_ERROR' => 'E_10017',
            'INVALID_APN_DEVICE_TOKEN_ERROR' => 'E_10019',
            'EMAIL_NOT_SENT_ERROR' => 'E_10021',
            'INVALID_OR_EXPIRED_TOKEN_ERROR' => 'E_10023',
            'DATA_NOT_SAVED_ERROR' => 'E_10025',
            'USER_NOT_AUTHANTICATE' => 'E_10026',
            'REQUEST_NOT_IN_FORMAT' => 'E_10027',
            'UNIQUE_EMAIL' => 'E_10028',
            'REGISTRATION_PROBLEM' => 'E_10045'
            );
        return ($status[$code]) ? $status[$code] : $status['ERROR'];
    }

    public function response($data = '', $status = '') {
        $this->_code = ($status) ? $status : 200;
        $this->_set_headers();
        echo $data;
        exit;
    }

    public function encryptMethod($response) {
        $this->render('/Restful/json/response_json');
    }

    public function _render() {
        try {
            if ($this->_extension === 'json') {
                $this->render('/Restful/json/response_json');
            } else if ($this->_extension == 'xml') {
                App::init('Xml', 'Utility');
                $this->render('/Restful/xml/response_xml');
            } else {
                $this->render('/Restful/json/response_json');
            }
        } catch (Exception $e) {
            throw new NotFoundException('File Restful/Server Not found');
        }
    }

    public function signUp() {
        $responses = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->User->set($this->request->data);
            if ($this->User->validates()) {
                $this->request->data['User']['role_id'] = AUDITOR_ROLE_ID;
                $Inforesult = $this->Users->saveAudit($this->request->data);
                /* Send Email Registerd User */
                // send email to user for activation
                $email = $this->request->data['email'];
                $name = $this->request->data['name'];
                $templateId = ACCOUNT_ACTIVATION_EMAIL_TEMPLATE_ID;
                $emailData ['receiver_email'] = !empty($email) ? trim($email) : NULL;
                $emailData ['receiver_name'] = !empty($name) ? trim($name) : NULL;
                $emailData ['link'] = Router::fullbaseUrl() . "/users/activation/" . base64_encode($email);
                if ($this->Email->sendAccountActivationEmail($templateId, $emailData)) {
                    $response = array('status' => 1, 'data' => 'Your account has been created. A confirmation email has been sent to ' . $email, 'message' => 'Your account has been created. A confirmation email has been sent to ' . $email);
                }
                /* End of the code */
            } else {
                $message = $this->Validates->errorSignUP($this->User->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    /**
     * * Function :checkUniqueEmail
     * @access private
     * Description : Function used for avoiding duplication of emailID
     * Date : 04th Nov 2014
     */
    function checkUniqueEmail($email = null) {
        $user = $this->User->find('all', array('conditions' => array('email' => $email), 'fields' => array('id')));
        if (!empty($user)) {
            return 1;
        } else {
            return 0;
        }
    }

    public function login() {      
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
//            echo "<pre>";
//            print_r($this->request->data);
//             die;
            $this->User->set($this->request->data);
            $this->request->data['User']['email'] = $this->request->data['email'];
            $this->request->data['User']['password'] = $this->request->data['password'];
            $this->request->data['User']['notification_token'] = $this->request->data['notification_token'];
            $this->User->setValidationLoginRules();
            if ($this->User->validates()) {
                $userDetail = $this->User->authenticate($this->request->data);
                if (!empty($userDetail)) {
                    $response = array();
                    $_token = $userDetail['User']['_token'];
                    if (!($_token))
                        App::uses('CakeText', 'Utility');
                    $token = CakeText::uuid();
                    $_token = $token;

                    $this->User->id = $userDetail['User']['id'];
                    //Save Token in the User table
                    if (!$this->User->saveField('_token', $_token)) {
                        $response = array('status' => '0', 'message' => 'Whoops, Device Token could not be saved.');
                    }
                    
                    if(!empty($this->request->data['User']['notification_token'])){
                        if($this->request->data['User']['notification_token'] != @$userDetail['User']['notification_token']){                            
                            $this->User->saveField('notification_token', $this->request->data['User']['notification_token']);
                        }                        
                    }
                    
                    

                    //User profile picture//
                    if (!empty($userDetail['User']['profile_pic'])) {
                        $user_avatar = Router::fullbaseUrl() . $userDetail['User']['profile_pic'];
                    } else {
                        $user_avatar = Router::fullbaseUrl() . '/img/profile-img.png';
                    }
                    //Check if user check in place  if yes then send check in place data back to native app
                    $userId = $userDetail['User']['id'];

                    $userData = array("username" => $userDetail['User']['username'],
                        "_token" => $_token, "id" => $userId, "name" => $userDetail['User']['name'], "email" => $userDetail['User']['email'], "address" => $userDetail['User']['address']
                        , "profile_pic" => $user_avatar, "is_active" => $userDetail['User']['is_active']
                        ,"system_admin_id" => $userDetail['User']['system_admin_id'],"notification_token" => !empty($userDetail['User']['notification_token']) ? $userDetail['User']['notification_token'] : '');
                    
                       
                    $response = array('status' => 1, 'data' => $userData);
                } else {
                    $response = array('status' => '0', 'message' => 'Please enter valid Email and Password and try again.', 'error_code' => $this->_get_error_code('USER_NOT_AUTHANTICATE'));
                }
            } else {
                $message = $this->Validates->errorLogin($this->User->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format',);
        }
        

        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    /*
     * Function Name : updateAuditerInfo
     * Function Decription : This function we have used to update auditer information
     */

    public function updateAuditerInfo() {
        if (!empty($this->request->data)) {
            $this->request->data['User']['name'] = $this->request->data['name'];
            $this->request->data['User']['address'] = $this->request->data['address'];
            $this->request->data['User']['id'] = $this->request->data['id'];
            /* Get login userdetail */
            $userDetail = $this->Users->getUserDetail($this->request->data['id']);
            $this->_user = $userDetail;
            /* End of the code */
            $userId = $this->_user['User']['id'];
            if (!empty($this->request->data['profile_pic'])) {
                $this->request->data['User']['profile_pic'] = $this->request->data['profile_pic'];
                $this->File = $this->Components->load('File');
                $this->File->initialize($this);
                $profilePic = $this->File->upload_media($userId, $this->request->data['User']['profile_pic']);
                $this->request->data['User']['profile_pic'] = $profilePic;
            }
            if ($this->User->save($this->request->data['User'])) {
                $userInfo = $this->User->find('first', array(
                    'conditions' => array('id' => $userId)
                ));
                if (!empty($userInfo)) {
                    if (!empty($userInfo['User']['profile_pic']))
                        $user_avatar = Router::fullbaseUrl() . $userInfo['User']['profile_pic'];
                    else
                        $user_avatar = Router::fullbaseUrl() . '/img/profile_user@2x.png';
                    $userData = array("username" => $userInfo['User']['username'],
                        "_token" => $userInfo['User']['_token'], "id" => $userId, "name" => $userInfo['User']['name'], "email" => $userInfo['User']['email'], "address" => $userInfo['User']['address']
                        , "profile_pic" => $user_avatar, "is_active" => $userInfo['User']['is_active']
                        );
                    $response = array('status' => 1, 'message' => 'Your profile updated sucessfully.', 'data' => $userData);
                }
                else {
                    $response = array('status' => '0', 'message' => 'Invalid data provide.', 'error_code' => $this->_get_error_code('INVALID_DATA_ERROR'));
                }
            }
        } else {
            $response = array('status' => '0', 'message' => 'Invalid data provide.', 'error_code' => $this->_get_error_code('INVALID_DATA_ERROR'));
        }
        $this->set('result', $response);
        $this->saveLogBeforeRetruning($response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    /*
     * Function Name : resetPassword
     * Function Description : This function we have used to reset password
     */

    public function resetPassword() {
        $response = array();
        App::uses('CakeText', 'Utility');
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->request->data['email'] = Sanitize::escape($this->request->data['email']);
            $this->request->data['_token'] = CakeText::uuid();
            $this->User->set_forgotpw_validation_rules();
            $this->User->set($this->request->data);
            if ($this->User->validates()) {
              $response = $this->Users->webResetPassword($this->request->data);
          } else {
              $message = $this->Validates->errorResetPassword($this->User->validationErrors);
              $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
          }
         } else {
              $response = array('status' => '0', 'message' => 'Data is not in post format',);
         }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }


    public function changePassword(){
       //Configure::write('debug',2); 
        $response = array();
        $this->loadModel('User');
        try{
            if ($this->request->isPost() && !empty($this->request->data)) {
                 $userArr = $this->User->find('first',array('conditions'=>array('User.id'=>$this->request->data['users_id'])));
                if(!empty($userArr)){             
                    $userPassword = $this->Auth->password($this->request->data['old_password']); 
                    $usernewpassword = $this->Auth->password($this->request->data['new_password']); 
                    if(!empty($userPassword) && ($userPassword == $userArr['User']['password'])){
                        if(!empty($this->request->data['new_password']) && ($this->request->data['new_password']==$this->request->data['confirm_password'])){
                            if($this->User->updateAll(array('User.password' => "'$usernewpassword'"), array('User.id' => $this->request->data['users_id']))){
                                $response = array('status' => '1', 'data' => 'password change successfully', 'message' => 'password change successfully');
                            } 
                        }else{
                            $response = array('status' => '0', 'message' => 'New password and confirm password is different',);
                        }
                    }else{
                      $response = array('status' => '0', 'message' => 'error in change password please try again',);
                  }
              }else{
               $response = array('status' => '0', 'message' => 'user Doesn\'t exists. ',);
             }
        }else{
            $response = array('status' => '0', 'message' => 'Data is not in post format',);
        }
        }catch(Exception $e){
            $response = array('status' => '0', 'message' => $e->getMessage());
        }      
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->saveLogBeforeRetruning($response);
        $this->_render();
    }


    public function auditListing() {        
        //Configure::write('debug',2); 
        $response = array();
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);          
        $response = array();
        if (!empty($this->request->data)){
            $type = 'all';                
                $conditions = array('Audit.process_id' => $this->request->data['office_id'],'Audit.clients_id' => $this->request->data['clients_id'], 'Audit.is_deleted' => BOOL_FALSE);
                $fields = array('Audit.*');
                $contain = NULL;
                $order = array('Audit.created_date' => 'ASC');
                $group = NULL;
                $recursive = 1;
                $this->loadModel('Audit');
                /* Get Auditor Listing */
                $auditList = $this->Audit->getAuditData($type, $conditions, $fields, $contain, $order, $group, $recursive);
                /* End of the code */
                $auditData = array();
                $i = 0;
                $j = 0;
                 // print_r($auditList);exit;
                foreach ($auditList as $auditID) {
                    $auditData[$i] = $auditID['Audit'];
                    if (!empty($auditID['AuditGroupSchedule'])) {
                        $arr = array();
                        foreach ($auditID['AuditGroupSchedule'] as $val) {
                            if ($val['start_time'] == "00:00:00") {
                                $val['start_time'] = "";
                            }
                            if ($val['finish_time'] == "00:00:00") {
                                $val['finish_time'] = "";
                            }
                            $schedule['schedule_date'] = $val['schedule_date'];
                            $schedule['start_time'] = date('h:i A', strtotime($val['start_time']));
                            $schedule['finish_time'] = date('h:i A', strtotime($val['finish_time']));
                 //  $schedule['groups_id'] = $val['groups_id'];
                 //  $schedule['group_name'] = $val['group_name'];
                            $arr[] = $schedule;
                        }
                        $auditData[$i]['schedule'] = $arr;
                    }
                    $i++;
                }
                $i = 0;
                foreach ($auditList as $auditID) {
                    if (!empty($auditID['AuditGroup'])) {
                        $arr1 = array();
                        foreach ($auditID['AuditGroup'] as $val) {
                 // $auditGrpArr['idauditGroup'] = $val['id'];
                            $auditGrpArr['groups_id'] = $val['groups_id'];
                            $auditGrpArr['group_name'] = $val['group_name'];
                 // $schedule['groups_id'] = $val['groups_id'];
                 // $schedule['group_name'] = $val['group_name'];
                            $arr1[] = $auditGrpArr;
                        }
                        $auditData[$i]['group'] = $arr1;
                    }
                    $i++;
                }
                if (isset($auditData)) {
                    $response = array('status' => 1, 'data' => $auditData);
                }
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }

    
    public function questionListing() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $questionData = $this->Audits->getAllClientQuestion($this->request->data['groups_id']);
            if (!empty($questionData)) {
                $response = array('status' => 1, 'data' => $questionData);
            } else {
//                $response = array('status' => '0', 'message' => "No any group available on this audit.");
                $response = array('status' => '0', 'message' => "No question available for this group");
            }
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    
    public function updateAudit() {       

        Configure::write('debug',0);
        $this->loadModel('Audit');
        $this->loadModel('AuditGroupSchedule');
        $this->loadModel('AuditGroup');
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);
        $response = array();
        if (isset($input_data) && !empty($input_data)) {
            $this->request->data['Audit']['id'] = Sanitize::escape($input_data['id']);
            $this->request->data['Audit']['audit_name'] = Sanitize::escape($input_data['audit_name']);
            $this->request->data['Audit']['auditer_name'] = Sanitize::escape($input_data['auditer_name']);
            $this->request->data['Audit']['audit_date'] = Sanitize::escape($input_data['audit_date']);
            $this->request->data['Audit']['audit_scope'] = Sanitize::escape($input_data['audit_scope']);
            $this->request->data['Audit']['client_name'] = Sanitize::escape($input_data['client_name']);
            $this->request->data['Audit']['contact_detail'] = Sanitize::escape($input_data['contact_detail']);
            $this->request->data['Audit']['amount_of_days_audit'] = Sanitize::escape($input_data['amount_of_days_audit']);
            $this->request->data['Audit']['audit_standards'] = Sanitize::escape($input_data['audit_standards']);
            $this->request->data['Audit']['clients_id'] = Sanitize::escape($input_data['clients_id']);
            $this->request->data['Audit']['users_id'] = Sanitize::escape($input_data['users_id']);
            $this->request->data['Audit']['contact_person_name'] = Sanitize::escape($input_data['contact_person_name']);
            $this->Audit->updateAuditValidation();
            $this->Audit->set($this->request->data);
            if ($this->Audit->validates()) {
                if ($this->Audit->save($this->request->data)) {
                    $res=$this->admin_reAuditPushNotification($this->request->data['Audit']['users_id'],$this->request->data['Audit']['audit_name'],$input_data['schedule'][0]['schedule_date']);      
//                    print_r($res);
                    $condition = array('AuditGroupSchedule.audits_id' => $input_data['id']);
                    $this->AuditGroupSchedule->deleteAll($condition, false);
                    foreach ($input_data['schedule'] as $Scheduledata) {
                        $this->request->data['AuditGroupSchedule']['schedule_date'] = $Scheduledata['schedule_date'];
                        $this->request->data['AuditGroupSchedule']['start_time'] = $Scheduledata['start_time'];
                        $this->request->data['AuditGroupSchedule']['audits_id'] = $input_data['id'];
                        // $this->request->data['AuditGroupSchedule']['groups_id'] = $Scheduledata['groups_id'];
                        $this->request->data['AuditGroupSchedule']['finish_time'] = $Scheduledata['finish_time'];
                        // $this->request->data['AuditGroupSchedule']['group_name'] = $Scheduledata['group_name'];
                        $this->AuditGroupSchedule->create();
                        $this->AuditGroupSchedule->save($this->request->data['AuditGroupSchedule']);
                    }
                    if (!empty($input_data['group'])) {
                        $condition = array('AuditGroup.audits_id' => $input_data['id']);
                        $this->AuditGroup->deleteAll($condition, false);
                        foreach ($input_data['group'] as $auditGroupData) {
                            $auditGrpArr['audits_id'] = Sanitize::escape($input_data['id']);
                            $auditGrpArr['groups_id'] = $auditGroupData['groups_id'];
                            $auditGrpArr['group_name'] = $auditGroupData['group_name'];
                            $this->AuditGroup->create();
                            $this->AuditGroup->save($auditGrpArr);
                        }
                    } else { // for deleting all the groups for the audits
                        $condition = array('AuditGroup.audits_id' => $input_data['id']);
                        $this->AuditGroup->deleteAll($condition, false);
                    }
                    $this->loadModel('PushNotification');
//                    $this->loadModel('SubadminAuditor');
//                    $SubadminAuditorArr = $this->SubadminAuditor->find('all', array('conditions' => array('SubadminAuditor.auditors_id' => $input_data['users_id'])));
//                    $this->request->data['PushNotification']['users_id'] = trim($input_data['users_id']);
//                    $this->request->data['PushNotification']['roles_id'] = trim(AUDITOR_ROLE_ID);
//                    $this->request->data['PushNotification']['message'] =  Sanitize::escape($input_data['auditer_name'] . " has been updated an audit on " . $input_data['audit_date'] . " with details " . "client name:" . $input_data['client_name'] . "," . " location of audit: " . $input_data['audit_name'] . "," . " contact person: " . $input_data['contact_person_name'] . "," . " contact person detail: " . $input_data['contact_detail'] . "," . " scope of audit: " . $input_data['audit_scope'] . "," . " standards: " . $input_data['audit_standards'] . "," . " number of days: " . $input_data['amount_of_days_audit']);
//                    $this->request->data['PushNotification']['type'] = Sanitize::escape("update audit");
//                    $PushNotificationArr1 = $this->PushNotification->save($this->request->data['PushNotification']);
//                    $PushNotificationArr ='';
//                    foreach ($SubadminAuditorArr as $SubadminAuditorNewArr) {
//                        $this->request->data['PushNotification']['users_id'] = trim($SubadminAuditorNewArr['SubadminAuditor']['subadmin_id']);
//                        $this->request->data['PushNotification']['roles_id'] = trim(SUB_ADMIN_ROLE_ID);
//                        $this->request->data['PushNotification']['message'] = Sanitize::escape($input_data['auditer_name'] . " has been created an audit on " . $input_data['audit_date'] . " with details " . "client name:" . $input_data['client_name'] . "," . " location of audit: " . $input_data['audit_name'] . "," . " contact person: " . $input_data['contact_person_name'] . "," . " contact person detail: " . $input_data['contact_detail'] . "," . " scope of audit: " . $input_data['audit_scope'] . "," . " standards: " . $input_data['audit_standards'] . "," . " number of days: " . $input_data['amount_of_days_audit']);
//                        $this->request->data['PushNotification']['type'] = Sanitize::escape("update audit");
//                        $this->PushNotification->create();
//                        $PushNotificationArr = $this->PushNotification->save($this->request->data['PushNotification']);
//                    }
//                    if ($PushNotificationArr || $PushNotificationArr1) {
//                        $response = array('status' => '1', 'data' => 'Audit updated sucessfully.', 'message' => 'Audit updated sucessfully.');
//                    } else {
//                        $response = array('status' => '0', 'message' => 'Problem in update audit notification.');
//                    }
                    
                    $users_id = trim($input_data['users_id']);
                    $role_id = trim(AUDITOR_ROLE_ID);
                    $message =  Sanitize::escape($input_data['auditer_name'] . " has been updated an audit on " . $input_data['audit_date'] . " with details " . "client name:" . $input_data['client_name'] . "," . " location of audit: " . $input_data['audit_name'] . "," . " contact person: " . $input_data['contact_person_name'] . "," . " contact person detail: " . $input_data['contact_detail'] . "," . " scope of audit: " . $input_data['audit_scope'] . "," . " standards: " . $input_data['audit_standards'] . "," . " number of days: " . $input_data['amount_of_days_audit']);
                    $type = Sanitize::escape("update audit");         
                    $notificationId = $this->UtilityFunction->saveCustomNotification($users_id, $role_id, $message, $type);
                    $assignSubAdminIds = $this->UtilityFunction->getSubAdminIdByAuditorId($users_id);
                    $this->UtilityFunction->sendCustomNotification($assignSubAdminIds, $notificationId);
                    if ($notificationId) {
                        $response = array('status' => '1', 'data' => 'Audit created sucessfully.', 'message' => 'Audit created sucessfully.');
                    } else {
                        $response = array('status' => '0', 'message' => 'Problem on send notification.');
                    }

                    $response = array('status' => '1', 'data' => 'Your audit updated sucessfully.', 'message' => 'Your audit updated sucessfully.');
                }
            } else {
                $message = $this->Validates->errorUpdateAuitProfile($this->Audit->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format',);
        }
        $this->saveLogBeforeRetruning(requestfor);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    
    public function admin_reAuditPushNotification($auditorId, $auditName, $date) {
        $token = $this->UtilityFunction->getNotificationTokenByAuditorId($auditorId);
        $message = "Your Audit " . $auditName . " has been ReScheduled on " . $date;
        $notificationId = $this->UtilityFunction->saveCustomNotification($auditorId, AUDITOR_ROLE_ID, $message, "Update Audit");
        $senderIds[] = $auditorId;
        $this->UtilityFunction->sendCustomNotification($senderIds, $notificationId);
        return $this->UtilityFunction->sendPushNotifications($token, $title);
    }

    public function groupListing() {
        Configure::write('debug',0);
        $response = array();
        if ($this->request->isPost()) {
        $type = 'all';
        $client_Id = $this->request->data['clients_id'];
        $officeId = $this->request->data['office_id'];
        $this->loadModel('Audit');
//        $auditData = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audit_Id)));
//        $officeId = $auditData['Audit']['process_id'];
        $this->loadModel('clientSubOffice');
        $clientSubOffice = $this->clientSubOffice->find('first', array('conditions' => array('clientSubOffice.clients_id' => $client_Id,'clientSubOffice.id' => $officeId)));

        if(count($clientSubOffice) > 0){
            $clientSubOfficeDefaultId = $clientSubOffice['clientSubOffice']['group_set_id'];
        }else{          
            $clientSubOfficeDefaultId = 0;
        }       

        if($officeId == 0 ){
            $conditions = array('Group.clients_id' => $client_Id, 'Group.is_deleted' => 0, 'Group.is_active' => 1);
        }else{
            $this->loadModel('GroupSetClient');
            $clientSubOffice = $this->GroupSetClient->find('first', array('conditions' => array('GroupSetClient.id' => $clientSubOfficeDefaultId)));
            $groupIds = $clientSubOffice['GroupSetClient']['group_ids'];
            $groupIdsArray = explode(",", $groupIds);
            $conditions = array('Group.id' => $groupIdsArray, 'Group.is_deleted' => 0, 'Group.is_active' => 1);
        } 


            $fields = array('Group.id', 'Group.description', 'Group.full_name', 'Group.is_active', 'Group.created_date', 'Group.audit_scope', 'Group.auditee', 'Group.audit_defination', 'Group.methods_id', 'Group.audit_method');
            
            $contain = NULL;
            $order = array('Group.sorting' => 'ASC');
            $group = NULL;
            $recursive = 0;
            $this->loadModel('Group');
            $groupList = $this->Group->getGroupData($type, $conditions, $fields, $contain, $order, $group, $recursive);
            $groupArray = array();
            foreach ($groupList as $group) {
                $group['Group']['description'] = Sanitize::stripTags($group['Group']['description'], 'b', 'p', 'div');
                $group['Group']['description'] = Sanitize::stripWhitespace($group['Group']['description']);
                $groupArray[] = $group['Group'];
            }
            if (isset($groupArray)) {
                $response = array('status' => 1, 'data' => $groupArray);
            }
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function addQuestion() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->request->data['Question']['question'] = Sanitize::escape($this->request->data['question']);
            $this->loadModel('Question');
            $this->loadModel('GroupQuestion');
            $this->Question->addQuestionValidation();
            $this->Question->set($this->request->data);
            if ($this->Question->validates()) {
                if ($this->Question->save($this->request->data['Question'])) {
                    $lastInsertID = $this->Question->getLastInsertId();
                    $this->request->data['GroupQuestion']['clients_id'] = $this->request->data['clients_id'];
                    $this->request->data['GroupQuestion']['groups_id'] = $this->request->data['groups_id'];
                    $this->request->data['GroupQuestion']['questions_id'] = $lastInsertID;
                    if ($this->GroupQuestion->save($this->request->data['GroupQuestion'])) {
                        $this->loadModel('PushNotification');
                        $this->loadModel('SubadminAuditor');
                        $this->loadModel('Client');
                        $clientArr = $this->Client->find('first', array('conditions' => array('Client.id' => $this->request->data['clients_id']), 'fields' => array('Client.client_name')));
                        $SubadminAuditorArr = $this->SubadminAuditor->find('all', array('conditions' => array('SubadminAuditor.auditors_id' => $this->request->data['id'])));
                        $this->request->data['PushNotification']['users_id'] = $this->request->data['id'];
                        $this->request->data['PushNotification']['roles_id'] = trim(AUDITOR_ROLE_ID);
                        $this->request->data['PushNotification']['message'] = Sanitize::escape($this->request->data['question'] . " question has been created by " . $clientArr['Client']['client_name']);
                        $this->request->data['PushNotification']['type'] = Sanitize::escape("Add Question");
                        $PushNotificationArr1 = $this->PushNotification->save($this->request->data['PushNotification']);
                        foreach ($SubadminAuditorArr as $SubadminAuditorNewArr) {
                            $this->request->data['PushNotification']['users_id'] = trim($SubadminAuditorNewArr['SubadminAuditor']['subadmin_id']);
                            $this->request->data['PushNotification']['roles_id'] = trim(SUB_ADMIN_ROLE_ID);
                            $this->request->data['PushNotification']['message'] = Sanitize::escape($this->request->data['question'] . " question has been created by " . $clientArr['Client']['client_name']);
                            $this->request->data['PushNotification']['type'] = Sanitize::escape("Add Question");
                            $this->PushNotification->create();
                            $PushNotificationArr = $this->PushNotification->save($this->request->data['PushNotification']);
                        }
                        if ($PushNotificationArr || $PushNotificationArr1) {
                            $response = array('status' => '1', 'data' => 'Your question sucessfully uploaded.', 'message' => 'Your question sucessfully uploaded');
                        }
                    }
                } else {
                    $response = array('status' => '0', 'message' => 'Problem on uploding. Please try again.');
                }
            } else {
                $message = $this->Validates->errorAddQuestion($this->Question->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function addGroup() {
        Configure::write('debug',0);
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            //  $this->request->data['Group']['group_short_name'] = Sanitize::escape($this->request->data['group_short_name']);
            $this->request->data['Group']['full_name'] = Sanitize::escape($this->request->data['full_name']);
            $this->request->data['Group']['description'] = Sanitize::escape($this->request->data['description']);
            $this->request->data['Group']['clients_id'] = trim($this->request->data['clients_id']);
            $this->request->data['Group']['methods_id'] = trim($this->request->data['methods_id']);
            $this->request->data['Group']['audit_scope'] = Sanitize::escape($this->request->data['audit_scope']);
            $this->request->data['Group']['auditee'] = Sanitize::escape($this->request->data['auditee']);
            $this->request->data['Group']['audit_defination'] = Sanitize::escape($this->request->data['audit_defination']);
            $this->request->data['Group']['audit_method'] = Sanitize::escape($this->request->data['audit_method']);
            //  print_r($this->request->data['Group']);die();
            $this->loadModel('Group');
            $this->Group->addGroupValidation();
            $this->Group->set($this->request->data);
            if ($this->Group->validates()) {
                if ($this->Group->save($this->request->data['Group'])) {
                    $this->loadModel('PushNotification');
                    $this->loadModel('SubadminAuditor');
                    $this->loadModel('Client');
                    $clientArr = $this->Client->find('first', array('conditions' => array('Client.id' => $this->request->data['clients_id']), 'fields' => array('Client.client_name')));
                    $SubadminAuditorArr = $this->SubadminAuditor->find('all', array('conditions' => array('SubadminAuditor.auditors_id' => $this->request->data['id'])));
                    $this->request->data['PushNotification']['users_id'] = $this->request->data['id'];
                    $this->request->data['PushNotification']['roles_id'] = trim(AUDITOR_ROLE_ID);
                    $this->request->data['PushNotification']['message'] = Sanitize::escape($this->request->data['full_name'] . " group has been created by " . $clientArr['Client']['client_name']);
                    $this->request->data['PushNotification']['type'] = Sanitize::escape("Add Group");
                    $PushNotificationArr1 = $this->PushNotification->save($this->request->data['PushNotification']);
                    foreach ($SubadminAuditorArr as $SubadminAuditorNewArr) {
                        $this->request->data['PushNotification']['users_id'] = trim($SubadminAuditorNewArr['SubadminAuditor']['subadmin_id']);
                        $this->request->data['PushNotification']['roles_id'] = trim(SUB_ADMIN_ROLE_ID);
                        $this->request->data['PushNotification']['message'] = Sanitize::escape($this->request->data['full_name'] . " group has been created by " . $clientArr['Client']['client_name']);
                        $this->request->data['PushNotification']['type'] = Sanitize::escape("Add Group");
                        $this->PushNotification->create();
                        $PushNotificationArr = $this->PushNotification->save($this->request->data['PushNotification']);
                    }
                    if ($PushNotificationArr || $PushNotificationArr1) {
                        $response = array('status' => '1', 'data' => 'Your group sucessfully added','message' => 'Your group sucessfully added');
                    }
                } else {
                    $response = array('status' => '0', 'message' => 'Problem on added. Please try again.');
                }
            } else {
                $message = $this->Validates->errorAddGroup($this->Group->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function auditGroupListing() {
        Configure::write('debug',0);
        $response = array();
        $this->loadModel('AuditGroupQuestionComment');
        if ($this->request->isPost() && !empty($this->request->data)) {
            $clients_id = $this->request->data['clients_id'];
            $auditID = $this->request->data['audits_id'];
            $groupData = $this->Audits->getAllGroupsByAuditId($clients_id, $auditID);
            //print_r($groupData); exit;
            foreach ($groupData as $key => $value) {                
                $questionData = $this->Audits->getAllClientQuestion($value['id'],$auditID);
                $noOfQuestion = 0;
                $answerQuestion = 0;
                foreach ($questionData as $questionList) {
                    $questionArr = $this->AuditGroupQuestionComment->find('first', array('conditions' => array('AuditGroupQuestionComment.groups_id' => $value['id'], 'AuditGroupQuestionComment.audits_id' => $auditID, 'AuditGroupQuestionComment.questions_id' => $questionList['id'])));                    
                    if(!empty($questionArr['AuditGroupQuestionComment'])){
                        if($questionArr['AuditGroupQuestionComment']['sample_answer'] == 'Y' or $questionArr['AuditGroupQuestionComment']['sample_answer'] == 'N' or $questionArr['AuditGroupQuestionComment']['sample_answer'] == 'NA' or $questionArr['AuditGroupQuestionComment']['sample_answer'] == 'as') {
                            $answerQuestion++;
                        }
                    }
                    $noOfQuestion++;
                }
                $groupData[$key]['noOfQuestion'] = $noOfQuestion;
                $groupData[$key]['answerQuestion'] = $answerQuestion;
                $groupData[$key]['unAnswerQuestion'] = $noOfQuestion - $answerQuestion;
            }
            if (isset($groupData)) {
                $response = array('status' => 1, 'data' => $groupData);
            } else {
//                $response = array('status' => '0', 'message' => "No any group available on this audit.");
                $response = array('status' => '0', 'message' => "No any group available on this audit.");
            }
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function auditGroupQuestion() {
        Configure::write('debug',0);
        $this->loadModel('AuditGroupColumn');
        $this->loadModel('AuditGroupQuestionComment');
        $this->loadModel('Question');
        $this->loadModel('AuditGroupQuestionExampleAnswer');
        $this->loadModel('AuditGroupComment');
        $this->loadModel('AuditPercentage');
        $this->loadModel('RunAuditUpdate');
        $this->loadModel('DefaultResponse');
        $this->loadModel('AuditGroupQuestion');
        $this->loadModel('Audit');
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $groupID  = $this->request->data['groups_id'];
            $auditID  = $this->request->data['audits_id'];
            $clientID = $this->request->data['clients_id'];
            $questionData = $this->AuditGroupQuestion->getAllClientQuestion($clientID,$auditID,$groupID);
            if(count($questionData) == 0){   
                $questionData = $this->Audits->getAllClientQuestion($this->request->data['groups_id'],$auditID);
            }       
            /*Added by Swati T 19 Dec 2018 start*/
            $dataArr = $this->AuditPercentage->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentage.clients_id' => $clientID, 'AuditPercentage.audits_id' => $auditID, "   AuditPercentage.percentage NOT IN ('','-','-1')"), 'group' => 'audits_id'));
            $dataArr1 = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.clients_id' => $clientID, 'AuditPercentage.audits_id' => $auditID)));
            /*Added by Swati T 19 Dec 2018 end*/
            $exampleArr = $this->AuditGroupColumn->find('all', array('conditions' => array('AuditGroupColumn.groups_id' => $groupID, 'AuditGroupColumn.audits_id' => $auditID, 'AuditGroupColumn.clients_id' => $clientID, 'AuditGroupColumn.is_active' => 1, 'AuditGroupColumn.is_deleted' => 0)));
            // pr
            // echo "string";
            $questionArr = $this->AuditGroupQuestionComment->find('all', array('conditions' => array('AuditGroupQuestionComment.groups_id' => $groupID, 'AuditGroupQuestionComment.audits_id' => $auditID, 'AuditGroupQuestionComment.clients_id' => $clientID)));
            $auditgroupcommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.groups_id' => $groupID, 'AuditGroupComment.audits_id' => $auditID, 'AuditGroupComment.clients_id' => $clientID, 'AuditGroupComment.is_deleted' => 0)));
            $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.groups_id' => $groupID, 'AuditPercentage.audits_id' => $auditID)));
            

            if ($AuditPercentageArr) {
                $auditperArr['end_time'] = $AuditPercentageArr[0]['AuditPercentage']['end_time'];
                if ($AuditPercentageArr[0]['AuditPercentage']['percentage'] == '') {
                    $auditperArr['total_percent'] = ''; //By Swati T
                } else if ($AuditPercentageArr[0]['AuditPercentage']['percentage'] == 0) {
                    $auditperArr['total_percent'] = 0; //By Swati T
                } else {
                    $auditperArr['total_percent'] = $AuditPercentageArr[0]['AuditPercentage']['percentage'];
                } // Modified by Swati T @ 21 Dec 2018
                $scoreArr = $auditperArr;
            }/*else{
                $auditperArr['total_percent'] = " ";
                $scoreArr = $auditperArr;
            }*/
            

            $scoreArr = array_merge($scoreArr, $runAuditArr);
            // End of the code 
            /*Added by Swati T 19 Dec 2018 start*/
            if($dataArr1){
                foreach ($dataArr1 as $dataPercent) {
                    $percentArr['audits_id'] =  $dataPercent['AuditPercentage']['audits_id'];
                    $percentArr['clients_id'] = $dataPercent['AuditPercentage']['clients_id'];
                    $percentArr['groups_id'] =  $dataPercent['AuditPercentage']['groups_id'];
                    $percentArr['percentage'] = $dataPercent['AuditPercentage']['percentage'];
                    $scoreArr['Percentage'][] = $percentArr;
                }
            }else{
                $scoreArr['Percentage'] = [];
            }

            $scoreArr['AvgPercentage'][] = $dataArr[0][0]['avgPercentage'];
            /*Added by Swati T 19 Dec 2018 end*/
            if (!empty($exampleArr) || !empty($questionArr) || !empty($auditgroupcommentArr)) {
                if ($auditgroupcommentArr) {
                    foreach ($auditgroupcommentArr as $auditgroupcommentNewArr) {
                        $auditArr['groups_id'] = $auditgroupcommentNewArr['AuditGroupComment']['groups_id'];
                        // $auditArr['audit_date'] = $auditgroupcommentNewArr['AuditGroupComment']['audit_date'];
                        $auditArr['percentage'] = $auditgroupcommentNewArr['AuditGroupComment']['percentage'];
                        $auditArr['comment'] = $auditgroupcommentNewArr['AuditGroupComment']['comment'];
                        $auditArr['action'] = $auditgroupcommentNewArr['AuditGroupComment']['action'];
                        $auditArr['image'] = $auditgroupcommentNewArr['AuditGroupComment']['image'];
                        $auditArr['tempImage'] = '';
                        $scoreArr['Group'][] = $auditArr;
                    }
                } else {
                    $scoreArr['Group'] = [];
                }

                if (!empty($exampleArr)) {
                    $i = 0;
                    foreach ($exampleArr as $exampleNewArr) {
                        $questionArr = $this->AuditGroupQuestionComment->find('first', array('conditions' => array('AuditGroupQuestionComment.groups_id' => $groupID, 'AuditGroupQuestionComment.audits_id' => $auditID, 'AuditGroupQuestionComment.clients_id' => $clientID)));

                        $AuditGroupQuestionCommentID = $questionArr['AuditGroupQuestionComment']['id'];

                        $answerArr = $this->AuditGroupQuestionExampleAnswer->find('all', array('conditions' => array('AuditGroupQuestionExampleAnswer.audit_group_question_comment_id' => $AuditGroupQuestionCommentID), 'fields' => array('AuditGroupQuestionExampleAnswer.answer')));                 
                            //$QuestionArr['Example'] = array();
                        $answerSampleQuestion = 0;
                        $totalSample = 0;

                        foreach ($answerArr as $answerNewArr) {
                            $ExampleArr['answered'] = $answerNewArr['AuditGroupQuestionExampleAnswer']['answer'];
                            if($answerNewArr['AuditGroupQuestionExampleAnswer']['answer'] != ''){
                                $answerSampleQuestion++;
                            }
                            $totalSample++;
                        }

                        //print_r($questionArr); exit;
                        $ExampleArr['totalSample'] = $totalSample;    
                        $ExampleArr['answered'] =  $answerSampleQuestion; 
                        $ExampleArr['unanswered'] = $totalSample - $answerSampleQuestion;  
                        $ExampleArr['columnname'] = $exampleNewArr['AuditGroupColumn']['columnname'];
                        $ExampleArr['groups_id'] = $exampleNewArr['AuditGroupColumn']['groups_id'];
                        $scoreArr['Example'][] = $ExampleArr;                        
                    }
                } else {
                    $scoreArr['Example'] = array();
                }

                $noOfQuestion = 0;
                $answerQuestion = 0;

                foreach ($questionData as $questionList) {

                    $questionArr = $this->AuditGroupQuestionComment->find('first', array('conditions' => array('AuditGroupQuestionComment.groups_id' => $groupID, 'AuditGroupQuestionComment.audits_id' => $auditID, 'AuditGroupQuestionComment.clients_id' => $clientID, 'AuditGroupQuestionComment.questions_id' => $questionList['id'])));

                    $responseArr = $this->DefaultResponse->find('first', array('conditions' => array('DefaultResponse.id' => $questionArr['AuditGroupQuestionComment']['default_response_id'])));

                    if (!empty($questionArr)) {
                        $QuestionArr['audits_id'] = $auditID;
                        $QuestionArr['groups_id'] = $groupID;
                        $QuestionArr['questions_id'] = $questionList['id'];
                        $QuestionArr['comment'] = $questionArr['AuditGroupQuestionComment']['comment'];
                        $QuestionArr['action'] = $questionArr['AuditGroupQuestionComment']['action'];
                        $QuestionArr['percentage'] = $questionArr['AuditGroupQuestionComment']['percentage'];
                        $QuestionArr['image'] = $questionArr['AuditGroupQuestionComment']['image'];                        
                        $QuestionArr['tempImage'] = '';
                        $QuestionArr['sample_answer'] = $questionArr['AuditGroupQuestionComment']['sample_answer'];
                        $QuestionArr['default_response_id'] = $questionArr['AuditGroupQuestionComment']['default_response_id']; // recently  added by Swati T @27 Dec 2018
                        $QuestionArr['default_response'] = $responseArr['DefaultResponse']['response'];
                        $QuestionArr['questionlist'] = $questionList['question'];
                        $AuditGroupQuestionCommentID = $questionArr['AuditGroupQuestionComment']['id'];                        
                        $count1 = count($exampleArr);
                        if($count1 > 0 ) {
                            $answerArr = $this->AuditGroupQuestionExampleAnswer->find('all', array('conditions' => array('AuditGroupQuestionExampleAnswer.audit_group_question_comment_id' => $AuditGroupQuestionCommentID), 'fields' => array('AuditGroupQuestionExampleAnswer.answer')));
                            $QuestionArr['Example'] = array();
                            if(count($answerArr) > 0 ){
                                foreach ($answerArr as $answerNewArr) {
                                    $Q[]['answer'] = $answerNewArr['AuditGroupQuestionExampleAnswer']['answer'];
                                    $QuestionArr['Example'] = $Q;
                                }
                            }else{
                                $Q[]['answer'] = ''; 
                                $QuestionArr['Example'] = $Q;  
                            }
                            if($QuestionArr['sample_answer'] != ''){
                                $answerQuestion++;
                            }
                        }
                        unset($Q);  
                        $scoreArr['Question'][] = $QuestionArr;
                    } else {
                        $count1 = count($exampleArr);
                        $QuestionArr['audits_id'] = $auditID;
                        $QuestionArr['groups_id'] = $groupID;
                        $QuestionArr['questions_id'] = $questionList['id'];
                        $QuestionArr['comment'] = '';
                        $QuestionArr['action'] = '';
                        $QuestionArr['percentage'] = '';
                        $QuestionArr['image'] = '';
                        $QuestionArr['tempImage'] = '';
                        $QuestionArr['sample_answer'] = '';
                        $QuestionArr['default_response_id'] = 0; //recently added by Swati T @ 27 Dec 2018
                        $QuestionArr['default_response'] = '';
                        $QuestionArr['questionlist'] = $questionList['question'];
                        $QuestionArr['Example'] = array();
                        for ($i = 0; $i < $count1; $i++) {
                            $Q[]['answer'] = '';
                            $QuestionArr['Example'] = $Q;
                        }
                        $scoreArr['Question'][] = $QuestionArr;
                    }
                    $noOfQuestion++;
                }
                $scoreArr['noOfQuestion'] = $noOfQuestion;
                $scoreArr['answerQuestion'] = $answerQuestion;
                $scoreArr['unAnswerQuestion'] = $noOfQuestion - $answerQuestion;
                // Get audit information like auditor name and date
                $RunAuditUpdateArr = $this->RunAuditUpdate->find('all', array('conditions' => array('RunAuditUpdate.groups_id' => $groupID, 'RunAuditUpdate.audits_id' => $auditID)));
                $someInfo = $this->Audit->find('first', array('conditions' => array('Audit.id' => $auditID)));                
                $scoreArr['audit_date'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'];
                if (empty($RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'])) {
                    $scoreArr['audit_date'] = $someInfo['Audit']['audit_date'];
                } else {
                    $scoreArr['audit_date'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'];
                }                
                if ($RunAuditUpdateArr[0]['RunAuditUpdate']['contact_person_name'] != '') {
                    $scoreArr['contact_person_name'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['contact_person_name'];
                } else {
                    $scoreArr['contact_person_name'] = $someInfo['Audit']['contact_person_name'];

                } 
                if (!empty($scoreArr)) {
                    $response = array('status' => 1, 'data' => $scoreArr);
                } else {
                    $response = array('status' => '0', 'message' => "No data found");
                }
            } else {
                $questionData = $this->Audits->getAllGroupsQuestion($clientID, $groupID, $auditID);
                $questionData['total_percent']= ''; // By Swati T @ 21 Dec 2018
                if (isset($questionData)) {
                    // Get Run Audit Updates Information 
                    $RunAuditUpdateArr = $this->RunAuditUpdate->find('all', array('conditions' => array('RunAuditUpdate.groups_id' => $groupID, 'RunAuditUpdate.audits_id' => $auditID)));           
                    $someInfo = $this->Audit->find('first', array('conditions' => array('Audit.id' => $auditID)));
                    $questionData['audit_date'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'];
                    if (empty($RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'])) {
                        $questionData['audit_date'] = $someInfo['Audit']['audit_date'];
                    } else {
                        $questionData['audit_date'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['audit_date'];
                    }
                    if ($RunAuditUpdateArr[0]['RunAuditUpdate']['contact_person_name'] != '') {
                        $questionData['contact_person_name'] = $RunAuditUpdateArr[0]['RunAuditUpdate']['contact_person_name'];
                    } else {
                        $questionData['contact_person_name'] = $someInfo['Audit']['contact_person_name'];

                    } 
                    $response = array('status' => 1,'syncdata'=>1, 'data' => $questionData);
                } else {
                 $response = array('status' => '0', 'message' => "No question available for this group.");
             }
         }
     }

         $this->saveLogBeforeRetruning($response);
         $this->set('result', $response);
         $this->set('_serialize', array('result'));
         $this->_render();
    }

    public function getNotifications() {
        $response = $this->UtilityFunction->getNotifications($this->request->data['id']);
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    

    public function deleteNotifications() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->request->data['PushNotification']['status'] = 2;
            $this->request->data['PushNotification']['id'] = $this->request->data['id'];
            $this->loadModel('PushNotification');
            if ($this->PushNotification->save($this->request->data['PushNotification'])) {
                $response = array('status' => '1', 'data' => 'Notification deleted sucessfully.', 'message' => 'Notification deleted sucessfully.',);
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format',);
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function getAllClients() {     
        Configure::write('debug',2);      
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->loadModel('Client');
             $clientList = $this->Client->find('all', array('conditions' => array('Client.auditor_id' => $this->request->data['id'],'Client.is_active =' => 1,'Client.is_deleted =' => 0),'fields'=>array('Client.client_name', 'Client.id')));
            if (isset($clientList)) {
                    foreach ($clientList as $client) {
                        $clientArray[] = $client['Client'];
                    }
                    $response = array('status' => 1, 'data' => $clientArray);
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
            }
        }

    /* added comment array latest updated */

    public function runAudit() {
        Configure::write('debug',2);
        $this->File = $this->Components->load('File');
        $this->File->initialize($this);
        $response = array();
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);
        
        $this->uses = array('Audit','AuditPercentage','RunAuditUpdate','AuditGroupColumn','AuditGroupComment','AuditGroupQuestionExampleAnswer','AuditGroupQuestionComment');

        if (isset($input_data) && !empty($input_data)) {
             // Check whether its over a month of the audit. then disable the update options         
            $monthAgoDate = date('Y-m-d', strtotime('-30 days'));
            $auditDateExpired = $this->Audit->find('count', array('conditions' => array('Audit.id' => $input_data['audits_id'],'Audit.audit_date >=' => $monthAgoDate)));
            $o = 0;
            $AuditGroupCommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.audits_id' => $input_data['audits_id'], 'AuditGroupComment.clients_id' => $input_data['clients_id'], 'AuditGroupComment.groups_id' => $input_data['groups_id'])));
            if ($AuditGroupCommentArr) {
                $AuditGroupCommentdeleteArr = $this->AuditGroupComment
                ->deleteAll(array('AuditGroupComment.audits_id' => $input_data['audits_id'], 'AuditGroupComment.clients_id' => $input_data['clients_id'], 'AuditGroupComment.groups_id' => $input_data['groups_id']));
            }
            
            foreach ($input_data['Group'] as $Groupdata) {
                if ($Groupdata['image'] != '') {
                    $profilePic1 = $this->File->upload_question_media($Groupdata['image']); 
                    $this->request->data['AuditGroupComment']['image'] = $profilePic1;
                } else {
                    $this->request->data['AuditGroupComment']['image'] = "";
                }
                $this->request->data['AuditGroupComment']['clients_id'] = $input_data['clients_id'];
                $this->request->data['AuditGroupComment']['percentage'] = $Groupdata['percentage'];
                $this->request->data['AuditGroupComment']['groups_id'] = $Groupdata['groups_id'];
                $this->request->data['AuditGroupComment']['comment'] = $Groupdata['comment'];
                $this->request->data['AuditGroupComment']['action'] = $Groupdata['action'];
                $this->request->data['AuditGroupComment']['audits_id'] = $input_data['audits_id'];                
                $this->AuditGroupComment->create();
                $this->AuditGroupComment->save($this->request->data['AuditGroupComment']);
                //$o++;
            }
            /* For save data in audit_group_columns first */
            $k = 0;
            if (empty($input_data['Example'])) {
                $AuditGroupColumnArr = $this->AuditGroupColumn->find('all', array('conditions' => array('AuditGroupColumn.audits_id' => $input_data['audits_id'], 'AuditGroupColumn.clients_id' => $input_data['clients_id'], 'AuditGroupColumn.groups_id' => $input_data['groups_id'])));
                if ($AuditGroupColumnArr) {
                    $AuditGroupColumndeleteArr = $this->AuditGroupColumn->deleteAll(array('AuditGroupColumn.audits_id' => $input_data['audits_id'], 'AuditGroupColumn.clients_id' => $input_data['clients_id'], 'AuditGroupColumn.groups_id' => $input_data['groups_id']));
                }
            } else {
                foreach ($input_data['Example'] as $Exampledata) {
                    $this->request->data['AuditGroupColumn']['columnname'] = $Exampledata['columnname'];
                    $this->request->data['AuditGroupColumn']['audits_id'] = $input_data['audits_id'];
                    $this->request->data['AuditGroupColumn']['groups_id'] = $Exampledata['groups_id'];
                    $this->request->data['AuditGroupColumn']['clients_id'] = $input_data['clients_id'];
                    $AuditGroupColumnArr = $this->AuditGroupColumn->find('all', array('conditions' => array('AuditGroupColumn.audits_id' => $input_data['audits_id'], 'AuditGroupColumn.clients_id' => $input_data['clients_id'], 'AuditGroupColumn.groups_id' => $input_data['groups_id'])));
                    if ($AuditGroupColumnArr && $k == 0) {
                        $AuditGroupColumndeleteArr = $this->AuditGroupColumn->deleteAll(array('AuditGroupColumn.audits_id' => $input_data['audits_id'], 'AuditGroupColumn.clients_id' => $input_data['clients_id'], 'AuditGroupColumn.groups_id' => $input_data['groups_id']));
                    }
                    $this->AuditGroupColumn->create();
                    $this->AuditGroupColumn->save($this->request->data['AuditGroupColumn']);
                    $k++;
                }
            }
            /* End of the code */
            /* For Save data in audit group question answer */
            $j = 0;
            $m = 0;
            $sa = 0; // sample answer
            $tq = 0; // Total Question
            foreach ($input_data['Question'] as $Exampledata) {
                if ($Exampledata['image'] != '') {                    
                    $profilePic = $this->File->upload_question_media($Exampledata['image']); 
                    $this->request->data['AuditGroupQuestionComment']['image'] = $profilePic;
                } else {
                    $this->request->data['AuditGroupQuestionComment']['image'] = "";
                }                
                $this->request->data['AuditGroupQuestionComment']['comment'] = $Exampledata['comment']; 
                $this->request->data['AuditGroupQuestionComment']['default_response_id'] = $Exampledata['default_response_id']; 
                $this->request->data['AuditGroupQuestionComment']['questions_id'] = $Exampledata['questions_id'];
                $this->request->data['AuditGroupQuestionComment']['audits_id'] = $input_data['audits_id'];
                $this->request->data['AuditGroupQuestionComment']['groups_id'] = $Exampledata['groups_id'];
                $this->request->data['AuditGroupQuestionComment']['clients_id'] = $input_data['clients_id'];
                $this->request->data['AuditGroupQuestionComment']['percentage'] = $Exampledata['percentage'];
                $this->request->data['AuditGroupQuestionComment']['action'] = $Exampledata['action'];

                if(!empty($Exampledata['sample_answer'])){
                    $this->request->data['AuditGroupQuestionComment']['sample_answer'] = $Exampledata['sample_answer'];
                }else{
                    if(count($Exampledata['Example']) > 0 ){
                        $ieEmpty = true; 
                        foreach($Exampledata['Example'] as $eValues){
                            if(!empty($eValues['answer'])){ $ieEmpty = false; }
                        }
                        if($ieEmpty){ $as = ''; } else{ $as = 'as'; }
                        $this->request->data['AuditGroupQuestionComment']['sample_answer'] = $as;
                    }else{
                        $this->request->data['AuditGroupQuestionComment']['sample_answer'] = '';  
                    }
                }                

                $tq++;
                if($Exampledata['percentage'] == '-'){
                    $sa++;
                }               

                if(!empty($Exampledata['questions_id'])){
                    $AuditGroupQuestionCommentArr = $this->AuditGroupQuestionComment->find('all', array('conditions' => array('AuditGroupQuestionComment.audits_id' => $input_data['audits_id'], 'AuditGroupQuestionComment.clients_id' => $input_data['clients_id'], 'AuditGroupQuestionComment.questions_id' => $Exampledata['questions_id'],'AuditGroupQuestionComment.groups_id' => $Exampledata['groups_id'])));
                    if ($AuditGroupQuestionCommentArr) {
                        $AuditGroupQuestionCommentdeleteArr = $this->AuditGroupQuestionComment->deleteAll(array('AuditGroupQuestionComment.audits_id' => $input_data['audits_id'], 'AuditGroupQuestionComment.clients_id' => $input_data['clients_id'], 
                            'AuditGroupQuestionComment.questions_id' => $Exampledata['questions_id'],
                            'AuditGroupQuestionComment.groups_id' => $Exampledata['groups_id']));
                    }
                }

                $this->AuditGroupQuestionComment->create();
                $this->AuditGroupQuestionComment->save($this->request->data['AuditGroupQuestionComment']);
                $j++;                

                if(count($Exampledata['Example']) > 0 ){                  
                    $exampleArr = $this->AuditGroupQuestionExampleAnswer->find('all', array('conditions' => array('AuditGroupQuestionExampleAnswer.audits_id' => $input_data['audits_id'], 'AuditGroupQuestionExampleAnswer.clients_id' => $input_data['clients_id'], 'AuditGroupQuestionExampleAnswer.groups_id' => $Exampledata['groups_id'], 'AuditGroupQuestionExampleAnswer.questions_id' => $Exampledata['questions_id'])));
                    if ($exampleArr) {
                        $deleteArr = $this->AuditGroupQuestionExampleAnswer->deleteAll(array('AuditGroupQuestionExampleAnswer.audits_id' => $input_data['audits_id'], 'AuditGroupQuestionExampleAnswer.clients_id' => $input_data['clients_id'], 
                         'AuditGroupQuestionExampleAnswer.groups_id' => $Exampledata['groups_id'], 
                         'AuditGroupQuestionExampleAnswer.questions_id' => $Exampledata['questions_id']));
                    }    
                    foreach ($Exampledata['Example'] as $questionExe) {
                        $lastInsertID = $this->AuditGroupQuestionComment->getLastInsertId();                
                        $this->request->data['AuditGroupQuestionExampleAnswer']['answer'] = $questionExe['answer'];
                        $this->request->data['AuditGroupQuestionExampleAnswer']['questions_id'] = $Exampledata['questions_id'];
                        $this->request->data['AuditGroupQuestionExampleAnswer']['audits_id'] = $input_data['audits_id'];
                        $this->request->data['AuditGroupQuestionExampleAnswer']['groups_id'] = $Exampledata['groups_id'];
                        $this->request->data['AuditGroupQuestionExampleAnswer']['clients_id'] = $input_data['clients_id'];
                        $this->request->data['AuditGroupQuestionExampleAnswer']['audit_group_question_comment_id'] = $lastInsertID;
                        $this->AuditGroupQuestionExampleAnswer->create();
                        $this->AuditGroupQuestionExampleAnswer->save($this->request->data['AuditGroupQuestionExampleAnswer']);
                        $m++;
                    }

                }
                
            } 


            $usersId  = $input_data['users_id'];
            $clientId = $input_data['clients_id'];
            $groupId  = $input_data['groups_id'];
            $auditId  = $input_data['audits_id'];            
            
            $response = $this->UtilityFunction->saveClientAuditQuestion($clientId,$groupId,$auditId,$usersId);
                 
            /* For save data in audit_group_comments */
            $this->request->data['AuditPercentage']['audits_id'] = $input_data['audits_id'];
            $this->request->data['AuditPercentage']['groups_id'] = $input_data['groups_id'];
            $this->request->data['AuditPercentage']['clients_id'] = $input_data['clients_id'];
         
            
            
             if ($input_data['total_percent'] == '-' || $tq == $sa ) {// commented by @vaibhavbargal
//            if ($input_data['total_percent'] == '-') {
                $this->request->data['AuditPercentage']['percentage'] = '-';
            }else if($input_data['total_percent']!='') {
                $this->request->data['AuditPercentage']['percentage'] = $input_data['total_percent'];
            }else{
                $this->request->data['AuditPercentage']['percentage'] = '';
            }

            $this->request->data['AuditPercentage']['end_time'] = $input_data['end_time'];

            $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.audits_id' => $input_data['audits_id'], 'AuditPercentage.clients_id' => $input_data['clients_id'], 'AuditPercentage.groups_id' => $input_data['groups_id'])));
            if ($AuditPercentageArr) {
                $AuditPercentagedeleteArr = $this->AuditPercentage->deleteAll(array('AuditPercentage.audits_id' => $input_data['audits_id'], 'AuditPercentage.clients_id' => $input_data['clients_id'], 'AuditPercentage.groups_id' => $input_data['groups_id']));
            }

            $this->AuditPercentage->save($this->request->data['AuditPercentage']);

            /* This code used for run audits information updates */
            $RunAuditArr = $this->RunAuditUpdate->find('all', array('conditions' => array('RunAuditUpdate.audits_id' => $input_data['audits_id'], 'RunAuditUpdate.clients_id' => $input_data['clients_id'], 'RunAuditUpdate.groups_id' => $input_data['groups_id'])));
            if ($RunAuditArr) {
                $RunAuditUpdatedeleteArr = $this->RunAuditUpdate->deleteAll(array('RunAuditUpdate.audits_id' => $input_data['audits_id'], 'RunAuditUpdate.clients_id' => $input_data['clients_id'], 'RunAuditUpdate.groups_id' => $input_data['groups_id']));
            }

            $this->request->data['RunAuditUpdate']['audits_id'] = $input_data['audits_id'];
            $this->request->data['RunAuditUpdate']['groups_id'] = $input_data['groups_id'];
            $this->request->data['RunAuditUpdate']['clients_id'] = $input_data['clients_id'];
            $this->request->data['RunAuditUpdate']['audit_date'] = $input_data['audit_date'];
            $this->request->data['RunAuditUpdate']['contact_person_name'] = $input_data['contact_person_name'];
            $this->RunAuditUpdate->save($this->request->data['RunAuditUpdate']);
            /* End of the code */

            $this->loadModel('PushNotification');
            $this->loadModel('SubadminAuditor');
            $this->loadModel('Audit');
            $auditArr = $this->Audit->find('first', array('conditions' => array('Audit.id' => $input_data['audits_id'])));
           
            //Notification start @vaibhav
            $users_id = trim($input_data['users_id']);
            $role_id = trim(SUB_ADMIN_ROLE_ID);
            $message = Sanitize::escape(" run audit has been done of " . $auditArr['Audit']['audit_name'] . " by " . $auditArr['Audit']['auditer_name']);
            $type = Sanitize::escape("run audit");
            $notificationId = $this->UtilityFunction->saveCustomNotification($users_id, $role_id, $message, $type);
            $assignSubAdminIds = $this->UtilityFunction->getSubAdminIdByAuditorId($users_id);
            $this->UtilityFunction->sendCustomNotification($assignSubAdminIds, $notificationId);
            //Notification end @vaibhav
            
            /* End of the code */
            /* Finally we have saved group comments */
            if ($notificationId) {
               $response = array('status' => '1' , 'data' => 'Your audit sucessfully completed', 'message' => 'Your audit sucessfully completed');
            }else {
                $response = array('status' => '0', 'message' => 'Data is not in post format',);
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        } else {
            $response = array('status' => '0', 'message' => 'Unable to process your request.');
        }

    }

    public function getClientDetail() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $clientDetail = $this->UtilityFunction->getClientDetail($this->request->data['clients_id']);
            if (isset($clientDetail) && !empty($clientDetail)) {
                $response = $clientDetail['Client'];
                $response = array('status' => '1', 'data' => $response, 'clientDetail' => $response);
            } else {
                $response = array('status' => '0', 'message' => 'Client detail not found.',);
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }

    /*
     * Function Name : getChartHistory
     * Function Description : This function we can used display chart parameter
     */

    public function getChartReport() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $clientDetail = $this->UtilityFunction->getClientDetail($this->request->data['clients_id']);
            if (isset($clientDetail) && !empty($clientDetail)) {
                $response = $clientDetail['Client'];
                $response = array('status' => '1',  'data' => $response, 'clientDetail' => $response);
            } else {
                $response = array('status' => '0', 'message' => 'Client detail not found.',);
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }

    /*
     * Function Name : createAudit
     * Function Description : This function we can used create new audit via auditer
     */

    public function createAudit() {
        Configure::write('debug',0);
        $response = array(); 
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);     
        if ($input_data && !empty($input_data)) {    
             
            $this->uses = array('Audit','AuditGroupSchedule','AuditGroup','PushNotification','SubadminAuditor');
            // Load all Model in array @vaibahv     
             $auditSchedules = $this->UtilityFunction->getAuditDetailByAuditorId($input_data['users_id']);
            foreach ($auditSchedules as $key => $auditSchedule) {
                foreach ($auditSchedule['AuditGroupSchedule'] as $value) {
                    $date = date_create($value['schedule_date']);
                    $schduelDate[] = $value['schedule_date'];
                }
            }

            $html = "";
            foreach ($input_data['schedule'] as $postScheduelDate) {
                if ($schduelDate) {                   
                    if (in_array($postScheduelDate['schedule_date'], $schduelDate)) {
                        $datecheck = true;
                        $html .= $postScheduelDate['schedule_date'] . " , ";
                    }
                }
            }

            if (@$datecheck) {
                $officeId = $this->request->data['Audit']['office_id'];
                $officeId = $this->Encryption->decrypt($officeId);
                $response = array('status' => '1', 'data' => "An audit has already been schedueled for the same day :" . rtrim($html, " , "),'message' => "Already schedueled for this dates :" . rtrim($html, " , "));
                $this->saveLogBeforeRetruning($response);
                $this->set('result', $response);
                $this->set('_serialize', array('result'));
                $this->_render();
            }
            $this->request->data['Audit']['users_id'] = trim($input_data['users_id']);
            $this->request->data['Audit']['clients_id'] = trim($input_data['clients_id']);
            $this->request->data['Audit']['audit_name'] = Sanitize::escape($input_data['audit_name']);
            $this->request->data['Audit']['auditer_name'] = Sanitize::escape($input_data['auditer_name']);
            $this->request->data['Audit']['audit_date'] = Sanitize::escape($input_data['audit_date']);
            $this->request->data['Audit']['audit_scope'] = Sanitize::escape($input_data['audit_scope']);
            $this->request->data['Audit']['client_name'] = Sanitize::escape($input_data['client_name']);
            $this->request->data['Audit']['contact_detail'] = Sanitize::escape($input_data['contact_detail']);
            $this->request->data['Audit']['amount_of_days_audit'] = Sanitize::escape($input_data['amount_of_days_audit']);
            $this->request->data['Audit']['audit_standards'] = Sanitize::escape($input_data['audit_standards']);
            $this->request->data['Audit']['contact_person_name'] = Sanitize::escape($input_data['contact_person_name']);
            $this->request->data['Audit']['contact_person_name'] = Sanitize::escape($input_data['contact_person_name']);
            $this->request->data['Audit']['system_admin_id'] = Sanitize::escape($input_data['system_admin_id']);
            $this->request->data['Audit']['process_id'] = Sanitize::escape($input_data['officeId']);            
            $this->Audit->saveAuditValidation();
            $this->Audit->set($this->request->data);
            if ($this->Audit->validates()) {
                if ($this->Audit->save($this->request->data['Audit'])) {
                    $lastInsertID = $this->Audit->getLastInsertId();
                    foreach ($input_data['group'] as $Groupdata) {
                        $this->request->data['AuditGroup']['audits_id'] = $lastInsertID;
                        $this->request->data['AuditGroup']['groups_id'] = $Groupdata['groups_id'];
                        $this->request->data['AuditGroup']['group_name'] = $Groupdata['group_name'];
                        $this->AuditGroup->create();
                        $this->AuditGroup->save($this->request->data['AuditGroup']);
                    }
                    
                    /* For Save data in audit group schedule */
                    foreach ($input_data['schedule'] as $Scheduledata) {
                        $this->request->data['AuditGroupSchedule']['schedule_date'] = $Scheduledata['schedule_date'];
                        if ($Scheduledata['start_time'] == "") {
                            $this->request->data['AuditGroupSchedule']['start_time'] = 0;
                        } else {
                            $this->request->data['AuditGroupSchedule']['start_time'] = $Scheduledata['start_time'];
                        }
                        $this->request->data['AuditGroupSchedule']['audits_id'] = $lastInsertID;
                        if ($Scheduledata['finish_time'] == "") {
                            $this->request->data['AuditGroupSchedule']['finish_time'] = 0;
                        } else {
                            $this->request->data['AuditGroupSchedule']['finish_time'] = $Scheduledata['finish_time'];
                        }
                        $this->AuditGroupSchedule->create();
                        $this->AuditGroupSchedule->save($this->request->data['AuditGroupSchedule']);
                    }   
//                  //added notification by @vaibhav//
                    $users_id = trim($input_data['users_id']);
                    $role_id = trim(AUDITOR_ROLE_ID);
                    $message = Sanitize::escape($input_data['auditer_name'] . " has been created an audit on " . $input_data['audit_date'] . " with details " . "client name:" . $input_data['client_name'] . "," . " location of audit: " . $input_data['audit_name'] . "," . " contact person: " . $input_data['contact_person_name'] . "," . " contact person detail: " . $input_data['contact_detail'] . "," . " scope of audit: " . $input_data['audit_scope'] . "," . " standards: " . $input_data['audit_standards'] . "," . " number of days: " . $input_data['amount_of_days_audit']);
                    $type =Sanitize::escape("create new audit");                  
                    $notificationId = $this->UtilityFunction->saveCustomNotification($users_id, $role_id, $message, $type);
                    $assignSubAdminIds = $this->UtilityFunction->getSubAdminIdByAuditorId($users_id);
                    $this->UtilityFunction->sendCustomNotification($assignSubAdminIds, $notificationId);
                    if ($notificationId) {
                        $response = array('status' => '1', 'data' => 'Audit created sucessfully.', 'message' => 'Audit created sucessfully.');
                    } else {
                        $response = array('status' => '0', 'message' => 'Problem on send notification.');
                    }
                } else {
                    $response = array('status' => '0', 'message' => 'Problem on save audit.');
                }
            } else {
                $message = $this->Validates->errorSaveAudit($this->Audit->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        } else {
            $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function updateQuestion() {
        $this->loadModel('Question');
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $question['Question'] = $this->data;
            $this->Question->updateQuestionValidation();
            $this->Question->set($this->request->data);
            if ($this->Question->validates()) {
                if ($this->Question->save($question)) {
                    $response = array('status' => '1', 'data' => 'Question updated sucessfully.', 'message' => 'Question updated sucessfully');
                } else {
                    $response = array('status' => '0', 'message' => 'Problem in update Question');
                }
            } else {
                $message = $this->Validates->errorUpdateQuestion($this->Question->validationErrors);
                $response = array('status' => '0', 'message' => $message, 'error_code' => $this->_get_error_code('VALIDATION_ERROR'));
            }
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function updateGroup() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->request->data['Group']['id'] = trim($this->request->data['id']);
     //            $this->request->data['Group']['group_short_name'] = Sanitize::escape($this->request->data['group_short_name']);
            $this->request->data['Group']['full_name'] = Sanitize::escape($this->request->data['full_name']);
            $this->request->data['Group']['description'] = Sanitize::escape($this->request->data['description']);
            $this->request->data['Group']['clients_id'] = trim($this->request->data['clients_id']);
            $this->request->data['Group']['audit_scope'] = Sanitize::escape($this->request->data['audit_scope']);
            $this->request->data['Group']['auditee'] = Sanitize::escape($this->request->data['auditee']);
            $this->request->data['Group']['audit_defination'] = Sanitize::escape($this->request->data['audit_defination']);
            $this->request->data['Group']['audit_method'] = Sanitize::escape($this->request->data['audit_method']);

            $this->loadModel('Group');
            $this->Group->addGroupValidation();
            //$this->Group->set($this->request->data);
            $groupupdate = '';
            if (!empty($this->request->data['id'])) {
                $groupupdate = $this->Group->updateAll(array('Group.full_name' => "'" . $this->request->data['full_name'] . "'", 'Group.description' => "'" . $this->request->data['description'] . "'", 'Group.audit_scope' => "'" . $this->request->data['audit_scope'] . "'", 'Group.auditee' => "'" . $this->request->data['auditee'] . "'", 'Group.audit_defination' => "'" . $this->request->data['audit_defination'] . "'", 'Group.audit_method' => "'" . $this->request->data['audit_method'] . "'"), array('Group.id' => $this->request->data['id'], 'Group.clients_id' => $this->request->data['clients_id']));
            }
            if ($groupupdate) {
                $response = array('status' => '1', 'data' => 'Group updated successfully', 'message' => 'Group updated successfully');
            } else {
                $response = array('status' => '0', 'message' => 'Problem on update. Please try again.');
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function updateExtraGroupInfo() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {

            $this->request->data['Group']['clients_id'] = trim($this->request->data['clients_id']);
            $this->request->data['Group']['audit_scope'] = !empty($this->request->data['audit_scope']) ? Sanitize::escape($this->request->data['audit_scope']) : '';
            $this->request->data['Group']['auditee'] = !empty($this->request->data['auditee']) ? Sanitize::escape($this->request->data['auditee']) : '';
            $this->request->data['Group']['audit_defination'] = !empty($this->request->data['audit_defination']) ? Sanitize::escape($this->request->data['audit_defination']) : '';
            $this->request->data['Group']['audit_method'] = !empty($this->request->data['audit_method']) ? Sanitize::escape($this->request->data['audit_method']) : '';

            $this->loadModel('Group');

            $thisd = $this->Group->updateAll(array('Group.audit_scope' => "'" . $this->request->data['audit_scope'] . "'", 'Group.auditee' => "'" . $this->request->data['auditee'] . "'", 'Group.audit_defination' => "'" . $this->request->data['audit_defination'] . "'", 'Group.audit_method' => "'" . $this->request->data['audit_method'] . "'"), array('Group.id' => $this->request->data['id'], 'Group.clients_id' => $this->request->data['clients_id']));

            if ($thisd) {
                $response = array('status' => '1', 'data' => 'Group updated successfully',  'message' => 'Group updated successfully');
            } else {
                $response = array('status' => '0', 'message' => 'Problem on update. Please try again.');
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function reportsClient() {
        $response = array();
        Configure::write('debug',0);
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->loadModel('AuditPercentages');
            $this->loadModel('Audit');
            $clientID = $this->request->data['clients_id'];

            $auditArr = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clientID, 'Audit.is_deleted' => 0), 'fields' => array('Audit.id'), 'recursive' => -1));

            if ($auditArr) {
                foreach ($auditArr as $auditNewArr) {

                    $options = array('conditions' => array('AuditPercentages.clients_id' => $clientID, 'AuditPercentages.audits_id' => $auditNewArr['Audit']['id'], "AuditPercentages.percentage NOT IN ('','-','-1',' ')"), 'fields' => array('AVG(AuditPercentages.percentage) as precentage', 'AuditPercentages.created_date', 'AuditPercentages.audits_id'));
                    //, 'group' => array('AuditPercentages.audits_id', 'YEAR(AuditPercentages.created_date)')
                    //, 'order' => array('YEAR(AuditPercentages.created_date)' => 'asc')
                    //'AuditPercentages.percentage !=' => 0, 
                    //Commented By Swati T @ 19 Dec 2018

                    /*$dataArr = $this->AuditPercentage->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentage.clients_id' => $clients_id, 
                                    'AuditPercentage.audits_id' => $audits_id, "
                                    AuditPercentage.percentage NOT IN ('','-','-1')"), 'group' => 'audits_id'));*/
                                    $dataArr[] = $this->AuditPercentages->find('all', $options);
                                }
                            }
                            $complyPercentage = 0;
                            if (!empty($dataArr)) {
                                foreach ($dataArr as $val) {
                                    if (!empty($val)) {
                                        $fields['year'][] = date('Y', strtotime($val[0]['AuditPercentages']['created_date']));
                                    }
                                }
                                $uniqueYear = array();
                                $uniqueYear = array_unique($fields['year']);
                                $finalresult = array();
                                $finalArr = array();
                                foreach ($uniqueYear as $val) {
                                    $i = 0;
                                    $newcount = 0;
                                    $complyPercentage = 0;
                                    $finalresult = array();
                                    foreach ($dataArr as $val1) {
                                        if (!empty($val1)) {
                                            $year = date('Y', strtotime($val1[0]['AuditPercentages']['created_date']));
                                            if ($val == $year) {

                                                if ($i == 0) {
                                                    $count = 0;
                                                } else {
                                                    $count = $newcount;
                                                }
                                                $x = reset($val1);
                                                $complyPercentage = $complyPercentage + $val1[0][0]['precentage'];
                                                $finalresult['year'] = $year;
                                                $totalcount = $count + 1;
                                                $newcount = $totalcount;
                                                $i++;
                                            }
                                        }
                                    }
                                    $totalPercentage = $complyPercentage / $newcount;

                                    $finalresult['percentage'] = round($totalPercentage, 0, PHP_ROUND_HALF_DOWN);
                                    if($finalresult['percentage'] > 0 ){ $finalArr[] = $finalresult; }

                                }


                                $response = array('status' => '1', 'message' => 'Audit Report of client', 'data' => $finalArr);
                            } else {
                                $response = array('status' => '0', 'message' => 'Not found audit report', 'data' => array());
                            }
                        } else {
                            $response = array('status' => '0', 'message' => 'Data is not in post format');
                        }
                        $this->saveLogBeforeRetruning($response);
                        $this->set('result', $response);
                        $this->set('_serialize', array('result'));
                        $this->_render();
                    }

                    public function reportListing() {
                        $response = array();
                        if ($this->request->isPost() && !empty($this->request->data)) {
                            $audits_id = !empty($this->request->data['audits_id']) ? trim($this->request->data['audits_id']) : null;
                            $type = 'all';
                            $conditions = array('AuditGroupQuestionComments.audits_id' => $audits_id);
                            $fields = array('AuditGroupQuestionComments.id', 'AuditGroupQuestionComments.action', 'Client.client_name', 'Audit.audit_date');
                            $contain = NULL;
                            $order = array('Audit.audit_date' => 'ASC');
                            $group = NULL;
                            $recursive = 0;
                            $this->loadModel('AuditGroupQuestionComments');
                            $reportData = $this->AuditGroupQuestionComments->getReportData($type, $conditions, $fields, $contain, $order, $group, $recursive);
                            $reportArray = array();
                            foreach ($reportData as $report) {
                                $report['AuditGroupQuestionComments']['id'] = Sanitize::stripWhitespace($report['AuditGroupQuestionComments']['id']);
                                $report['AuditGroupQuestionComments']['action'] = Sanitize::stripWhitespace($report['AuditGroupQuestionComments']['action']);
                                $report['AuditGroupQuestionComments']['client_name'] = Sanitize::stripWhitespace($report['Client']['client_name']);
                                $report['AuditGroupQuestionComments']['audit_date'] = Sanitize::stripWhitespace($report['Audit']['audit_date']);
                                $reportArray[] = $report['AuditGroupQuestionComments'];
                            }
                            if (!empty($reportArray)) {
                                $response = array('status' => 1, 'data' => $reportArray);
                            } else {
                                $response = array('status' => '0',  'message' => "No record available on this audit.");
                            }
                        } else {
                            $response = array('status' => '0', 'message' => 'Data is not in post format');
                        }
                        $this->saveLogBeforeRetruning($response);
                        $this->set('result', $response);
                        $this->set('_serialize', array('result'));
                        $this->_render();
                    }

                    public function deleteQuestion() {
        //configure::write('debug',2);
                        $response = array();
                        if ($this->request->isPost() && !empty($this->request->data)) {
                            $this->loadModel('Question');
                            $this->loadModel('GroupQuestion');
                            $que_id = trim($this->request->data['questions_id']);
                            $grup_id = trim($this->request->data['groups_id']);
                            $client_id = trim($this->request->data['clients_id']);
                            $chkQuestion = $this->GroupQuestion->find('first', array('conditions' => array('GroupQuestion.questions_id' => $que_id, 'GroupQuestion.groups_id' => $grup_id, 'GroupQuestion.clients_id' => $client_id)));

                            if (!empty($chkQuestion)) {
                //  if ($this->Question->saveField('is_deleted', BOOL_TRUE)) {
                                if ($this->Question->updateAll(array('Question.is_deleted' => BOOL_TRUE), array('Question.id' => $que_id))) {
                                    $updateQuestion = $this->GroupQuestion->updateAll(array('GroupQuestion.is_deleted' => BOOL_TRUE), array('GroupQuestion.questions_id' => $que_id, 'GroupQuestion.groups_id' => $grup_id, 'GroupQuestion.clients_id' => $client_id));

                                    if (isset($updateQuestion)) {
                                        $response = array('status' => '1', 'data' => 'Question deleted sucessfully.', 'message' => 'Question deleted sucessfully.');
                                    } else {
                                        $response = array('status' => '0', 'message' => 'Problem on delete.');
                                    }
                                } else {
                                    $response = array('status' => '0', 'message' => 'Problem on delete.');
                                }
                            } else {
                                $response = array('status' => '0', 'message' => 'Wrong input');
                            }
                        } else {
                            $response = array('status' => '0', 'message' => 'Data is not in post format');
                        }
                        $this->saveLogBeforeRetruning($response);
                        $this->set('result', $response);
                        $this->set('_serialize', array('result'));
                        $this->_render();
                    }

                    public function deleteGroup() {
                        $response = array();
                        if ($this->request->isPost() && !empty($this->request->data)) {
                            $this->loadModel('Group');
            $this->loadModel('AuditGroup'); // By Swati T @ 02 Jan 2019
            $this->Group->id = trim($this->request->data['id']);
            if ($this->Group->saveField('is_deleted', BOOL_TRUE)) {
                $this->AuditGroup->deleteAll(array('AuditGroup.groups_id' => $this->Group->id)); // By Swati T @ 02 Jan 2019
                $response = array('status' => '1', 'data' => 'Group deleted sucessfully.', 'message' => 'Group deleted sucessfully');
            } else {
                $response = array('status' => '0', 'message' => 'Problem on update. Please try again.');
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function contactUs() {
        $response = array();
        $this->loadModel('SiteContent');
        $contactus = $this->SiteContent->find('first', array('conditions' => array('SiteContent.id' => CONTACT_US_ID), 'fields' => array('SiteContent.content')));
        if (isset($contactus) && !empty($contactus)) {
            $response = $contactus['SiteContent']['content'];
            $response = array('status' => '1', 'data' => $response);
        } else {
            $response = array('status' => '0', 'message' => 'contact us not found.',);
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function privacyPolicy() {
        $response = array();
        $this->loadModel('SiteContent');
        $this->loadModel('UploadedDocument');
        $privacypolicy = $this->SiteContent->find('first', array('conditions' => array('SiteContent.id' => PRIVACY_POLICY_ID), 'fields' => array('SiteContent.content')));
        $uploadedDocs = $this->UploadedDocument->find('all', array('conditions' => array('UploadedDocument.site_content_id' => PRIVACY_POLICY_ID), 'fields' => array('UploadedDocument.file_name')));

        foreach ($uploadedDocs as $key => $document) {
            $responseImg[]= SITE_LINK.'/documents/'.$document['UploadedDocument']['file_name']; 
        }

        if (isset($privacypolicy) && !empty($privacypolicy)) {
            $response = $privacypolicy['SiteContent']['content'];                      
            $data['privacyPolicy'] = $response;
            $data['documents'] = $responseImg;
            $response = array('status' => '1', 'data' => $data);
        } else {
            $response = array('status' => '0', 'message' => 'privacy policy not found.');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    /* send audit date and details to mobile */

    public function getAuditDate() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->uses = array('Audit', 'Leave');
            $leavesData = $this->Leave->find('all', array('Leave' => array('Leave.users_id' => $this->request->data['users_id'])));
            foreach ($leavesData as $key => $leaves) {
                $auditDetails['leaves'][] = $leaves['Leave'];
            }
            $auditDetails['allSchedule'] = $this->Audits->getAllAuditsDate($this->request->data['users_id']);
            if (isset($auditDetails)) {
                $response = array('status' => 1, 'data' => $auditDetails);
            } else {
                $response = array('status' => 0, 'message' => 'Audit not found.');
            }
        } else {
            $response = array('status' => 0, 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    public function getLeaveDays() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->uses = array('Audit', 'Leave');
            $leavesData = $this->Leave->find('all', array('Leave' => array('Leave.users_id' => $this->request->data['users_id'])));
            foreach ($leavesData as $key => $leaves) {
                $leaveDetails[] = $leaves['Leave'];
            }
            if (isset($leaveDetails)) {
                $response = array('status' => 1, 'data' => $leaveDetails);
            } else {
                $response = array('status' => 0, 'message' => 'leave not found.');
            }
        } else {
            $response = array('status' => 0, 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function deleteAudit() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->loadModel('Audit');
            $this->loadModel('AuditGroupComment');
            $this->loadModel('AuditCancle');
            $this->Audit->id = trim($this->request->data['id']);
            $message = !empty($this->request->data['message']) ? $this->request->data['message'] : "-";
            $id = trim($this->request->data['id']);
            $fields['is_deleted'] = BOOL_TRUE;
            $conditions = array('Audit.id' => $id);
            $conditions1 = array('AuditGroupComment.audits_id' => $id);
            $updateArr = $this->Audit->updateAll($fields, $conditions);
            $AuditGroupCommentArr = $this->AuditGroupComment->updateAll($fields, $conditions1);
            $auditAllData = $this->Audit->find('all', array(
                'joins' => array(
                    array(
                        'table' => 'users',
                        'alias' => 'UserJoin',
                        'type' => 'INNER',
                        'conditions' => array(
                            'UserJoin.id = Audit.users_id'
                        )
                    ),
                    array(
                        'table' => 'clients',
                        'alias' => 'ClientJoin',
                        'type' => 'INNER',
                        'conditions' => array(
                            'ClientJoin.id = Audit.clients_id'
                        )
                    ),
                    array(
                        'table' => 'client_sub_offices',
                        'alias' => 'offices',
                        'type' => 'INNER',
                        'conditions' => array(
                            'offices.id = Audit.process_id'
                        )
                    )
                ),
                'conditions' => array(
                    'Audit.id' => $id
                ),
                'fields' => array('UserJoin.name', 'UserJoin.system_admin_id', 'Client.client_name', 'offices.label', 'Audit.audit_name', 'Audit.users_id'),
            ));
            
            $type = "Cancel Audit";
            $message = ucfirst($auditAllData[0]['UserJoin']['name']) . " has been cancelled this Auditudit: " . ucfirst($auditAllData[0]['Audit']['audit_name']).".<br> Reason: ".$message;
            $notificationId = $this->UtilityFunction->saveCustomNotification($auditAllData[0]['Audit']['users_id'], AUDITOR_ROLE_ID, $message, $type);
            $senderIds = $this->UtilityFunction->getUserByRoleId(SUB_ADMIN_ROLE_ID, $auditAllData[0]['UserJoin']['system_admin_id']);
            $assignSubAdminIds = $this->UtilityFunction->getSubAdminIdByAuditorId($auditAllData[0]['Audit']['users_id']);
            $system_admin_id[] = $auditAllData[0]['UserJoin']['system_admin_id'];
            $senderIds = array_merge($assignSubAdminIds, $system_admin_id);           
            $this->UtilityFunction->sendCustomNotification($senderIds, $notificationId);
            if ($updateArr && $AuditGroupCommentArr) {
                $response = array('status' => '1', 'data' => 'Audit deleted sucessfully', 'message' => 'Audit deleted sucessfully');
            } else {
                $response = array('status' => '0', 'message' => 'Problem in delete Audit. Please try again.');
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function reportsClientDetail() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $year = $this->request->data['year'];
            $clientID = $this->request->data['clients_id'];
            $this->loadModel('AuditPercentages');
            $this->loadModel('Audit');
            $auditArr = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clientID, 'Audit.is_deleted' => 0), 'fields' => array('Audit.id,Audit.audit_name'), 'recursive' => -1));
            if ($auditArr) {
                $dataArr = array();
                foreach ($auditArr as $auditNewArr) {
                    $dataArr = $this->AuditPercentages->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentages.clients_id' => $clientID, 'AuditPercentages.percentage !=' => 0, 'AuditPercentages.audits_id' => $auditNewArr['Audit']['id'], 'YEAR(AuditPercentages.created_date)' => $year), 'group' => 'audits_id'));
                    if (!empty($dataArr)) {
                        foreach ($dataArr[0] as $dataNewArr) {
                            $fields['audit_name'] = $auditNewArr['Audit']['audit_name'];
                            $fields['percentage'] = round($dataNewArr['avgPercentage'], 0, PHP_ROUND_HALF_DOWN);
                            $finalDataArr[] = $fields;
                        }
                    }
                }
            }
            if (!empty($finalDataArr)) {
                $response = array('status' => '1', 'message' => 'Details of audit', 'data' => $finalDataArr);
            } else {
                $response = array('status' => '0', 'message' => 'No details found', 'data' => array());
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function testpdf() {
        $this->layout = 'pdf';
        $params = array(
            'download' => false,
            'name' => "test.pdf",
            'paperOrientation' => 'portrait',
            'paperSize' => 'legal'
            );
        $this->set($params);
        $this->render();
    }

    public function demo_pdf() {
        $val = $this->requestAction('/managements/admin_testdemopdf');
        $categories = array('2001', '2002', '2003', '2004');
        $this->set("yearJson", json_encode($categories));
        $viewData = array(58, 34, 28, 20);
        $this->set("dataJson", json_encode($viewData));
    }

    /* This function is used to send the pdf through email
     * 
     */

    public function reportclientpdf() {

        configure::write('debug',0);
        $response = array();

        if ($this->request->isPost() && !empty($this->request->data)) {
           $audits_id = $this->request->data['audits_id'];
           $clients_id = $this->request->data['clients_id'];
           $email = $this->request->data['email'];

           App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
           $this->loadModel('Audit');
           $this->loadModel('Client');
           $this->loadModel('Question');
           $this->loadModel('AuditGroupQuestionComments');
           $this->loadModel('AuditGroupComment');
           $this->loadModel('User');
           $this->loadModel('AuditGroupQuestion');

           $scoreArr = array();
           $getArr = array();
           if ($clients_id != null && $audits_id != null) {
            $getArr = $this->AuditGroupQuestion->getAuditsQuestionsArr($clients_id, $audits_id);
        }

        if (!empty($getArr)) {
            $pdfname = "auditReportPdf" . time().".pdf";
            $i = 0;
            $contact_person_name = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.contact_person_name')));
            foreach ($getArr as $auditID) {
                $auditData['Audit'] = $auditID['Audit'];
                $companyName = $auditID['Client']['company_name'];            
                $clients_id = $auditID['Audit']['clients_id'];
                if (!empty($clients_id)) {
                    $getClientDetail = $this->Client->find('first', array('conditions' => array('Client.id' => $clients_id)));
                    if (!empty($getClientDetail)) {
                        $clientDetail['client_email'] = $getClientDetail['Client']['email'];
                        $clientDetail['client_contact'] = $getClientDetail['Client']['contact_name'];
                        $clientDetail['client_contact_name'] = $getClientDetail['Client']['client_name'];
                        $clientDetail['phone_number'] = $getClientDetail['Client']['phone_number'];
                        $auditData['clientDtail'] = $clientDetail;
                    } else {
                        $auditData['clientDtail'] = array();
                    }
                }

                $dataArr[0][0]['avgPercentage'] = '100';

                if (!empty($auditID['AuditGroup'])) {
                    foreach ($auditID['AuditGroup'] as $val) {
                        $groupArrID[] = $val['groups_id'];
                        $getCompyNScore = $this->AuditGroupQuestionComments->getAllComplyScore($val['groups_id'], $audits_id, $clients_id);
                        $AuditGroupCommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.groups_id' => $val['groups_id'], 'AuditGroupComment.audits_id' => $audits_id, 'AuditGroupComment.clients_id' => $clients_id, 'AuditGroupComment.is_deleted' => 0, 'AuditGroupComment.action' => array('NC','OB')), 'fields' => array('AuditGroupComment.comment,AuditGroupComment.action,AuditGroupComment.image,AuditGroupComment.groups_id')));

                               // echo "<pre/>";
                               // print_r($AuditGroupCommentArr);
                               // echo "<hr>";
                              // print_r($this->AuditGroupComment->getDataSource()->getLog(0,0));
                               //exit;

                        $question = "";
                        if (!empty($getCompyNScore)) {
                                //
                            foreach ($getCompyNScore as $getCompyNScoreArr) {
                                    //print_r($groupEndTime);
                                $queGrpID = !empty($getCompyNScoreArr['AuditGroupQuestionComments']['questions_id']) ? $getCompyNScoreArr['AuditGroupQuestionComments']['questions_id'] : 0;
                                $getQuestion = $this->Question->find('first', array('conditions' => array('Question.id' => $queGrpID)));
                                $question = !empty($getQuestion['Question']['question']) ? $getQuestion['Question']['question'] : "";
                                $dataArr['audit_question'] = $getQuestion['Question']['question'];
                                    //$dataArr['percentage'] = $getCompyNScoreArr['AuditGroupQuestionComments']['percentage'];
                                $dataArr['comment'] = $getCompyNScoreArr['AuditGroupQuestionComments']['comment'];
                                $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image'];
                                $dataArr['action_code'] = $getCompyNScoreArr['AuditGroupQuestionComments']['action'];
                                $dataArr['groupName'] = $val['group_name'];

                                    //                                        $dataArr['percentage'] = $groupEndTime['AuditGroupComment']['percentage'];
                                    //print_r($dataArr);
                                $scoreArr[] = $dataArr;
                            }

                            $this->loadModel('AuditPercentage');
                            $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.audits_id' => $audits_id, 'AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage !=' => ''), 'fields' => array('AuditPercentage.end_time', 'AuditPercentage.percentage', 'AuditPercentage.groups_id'), 'order' => array('AuditPercentage.groups_id ASC')));

                            $dataArr = $this->AuditPercentage->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentage.clients_id' => $clients_id, 
                                'AuditPercentage.audits_id' => $audits_id, "
                                AuditPercentage.percentage NOT IN ('','-','-1',' ')"), 'group' => 'audits_id'));
                                //print_r($dataArr); exit;
                                /*'AuditPercentage.percentage !=' => 0, */ //By Swati T @14Dec2018
                                $auditData['complyScore1'] = array();

                                // echo "AuditPercentageArr";
                                // echo "<pre/>";
                                // print_r($dataArr);
                                // exit;
                                foreach ($AuditPercentageArr as $AuditPercentageNewArr) {
                                    // echo "<pre/>";
                                    // print_r($AuditPercentageNewArr); 
                                    $groupInfo = $this->Audits->getAllGroupsByGroupId($AuditPercentageNewArr['AuditPercentage']['groups_id']);
                                    $dataArr1['percentage'] = $AuditPercentageNewArr['AuditPercentage']['percentage'];
                                    $dataArr1['end_time'] = $AuditPercentageNewArr['AuditPercentage']['end_time'];
                                    $dataArr1['groupName1'] = $groupInfo[0]['full_name'];

                                    $auditData['complyScore1'][] = $dataArr1;
                                }
                            }

                            

                            if (!empty($AuditGroupCommentArr)) {
                                //pr($AuditGroupCommentArr);
                                 //$scoreArrAudit = array();
                                foreach ($AuditGroupCommentArr as $AuditGroupCommentNewArr) {

                                    // $groupID= $AuditGroupCommentNewArr['AuditGroupComment']['groups_id'];
                                    //$groupName[0]['AuditGroup']['group_name'] = $this->AuditGroup->find('all',array('conditions'=>array('AuditGroup.groups_id'=>$groupID),'fields' => array('AuditGroup.group_name')));
                                    $dataArr['comment'] = $AuditGroupCommentNewArr['AuditGroupComment']['comment'];
                                    $dataArr['image'] = $AuditGroupCommentNewArr['AuditGroupComment']['image'];
                                    $dataArr['action_code'] = $AuditGroupCommentNewArr['AuditGroupComment']['action'];
                                    $dataArr['audit_question'] = "";
                                    $dataArr['groupName'] = $val['group_name'];
                                    $scoreArr[] = $dataArr;

                                    
                                }
                            }

                            $i++;
                        }
                        $auditData['complyScore'] = $scoreArr;
                    } else {
                     $auditData['complyScore'] = $scoreArr;
                 }
                 $i++;
                 $scheduleDateArr = array();
                 if (!empty($auditID['AuditGroupSchedule'])) {
                    foreach ($auditID['AuditGroupSchedule'] as $val1) {
                        $schedulArr[] = $val1['schedule_date'];
                    }
                    $auditData['scheduledates'] = $schedulArr;
                } else {
                    $auditData['scheduledates'] = array();
                }
            }


                // print_r($auditData);
                // exit;

            $content = '<style>               
            body, table, td, p, a, li, blockquote {
                -webkit-text-size-adjust: none !important;
                font-family: Arial;
                color: #666;
                font-size: 14px;
            }
            element.style {
                font-size: 14px;
            }
                *::after, *::before {
            box-sizing: border-box;
        }
                *::after, *::before {
        box-sizing: border-box;
    }
    b, strong {
        font-weight: 700;
    }
                * {
    box-sizing: border-box;
}
label {
    cursor: default;
}
body {
    font-family: "Open Sans",sans-serif;
    line-height: 1.42857;
    font-size: 14px;
    line-height: 1.42857;
}
                *::after, *::before {
box-sizing: border-box;
}
                *::after, *::before {
box-sizing: border-box;
}
.mar-0-auto{
    margin: 0 auto;
}
.tbl-border-white{
    border: 1px solid #fff
}
.tbl-border-white td, .tbl-border-white th{
    border: 1px solid #fff;
    padding: 10px;
}
.tbl-border-black{
    border: 1px solid #fff;
}
.tbl-border-black td, .tbl-border-black th{
    border: 1px solid #333;
    padding: 10px;
}
.tbl-border-blackk td, .tbl-border-blackk th{
    border: 1px solid #fff;
    border-bottom-width:3px;
    padding: 10px;
}
@page :first{
    background: #00b3ec;
}
@page :last{
    background: #00b3ec;
}
@page {
  size: auto;
  odd-header-name: html_MyHeader1;
  odd-footer-name: html_MyFooter1;
}
</style>
<body>
    <table border="0" cellpadding="0" cellspacing="0" width="100%" class="mar-0-auto">
        <tr>
            <td>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td>
                            <img src="images/logo_new.png" alt="">
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 32px; color: #000; font-weight: 600">
                            Audit Report for
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 70px; color: #fff; font-weight: 600; text-transform: uppercase">
                            '.$companyName.'
                        </td>
                    </tr>
                </table><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
                <table cellpadding="0" cellspacing="0" width="100%" class="tbl-border-white" style="margin: 30px 0px; ">
                    <tr>
                        <td rowspan="4" style="font-size: 18px; color: #fff;">
                            <strong> Prepared for:</strong><br/>
                            ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '<br/>
                            ' . $auditData["Audit"]["client_name"] . '<br/>
                            ' . $auditData["clientDtail"]["phone_number"] . '<br>
                            ' . $auditData["clientDtail"]["client_email"] . '
                        </td>';
                        /*Code modification done by swati T 04-12-2018 start*/
                        $msg2 = '';                                        
                        $msg2 .= '<td style="font-size: 18px; color: #fff;">';
                        $msg2 .= '<strong> Dates: </strong><br/>'; 
                                        /*foreach ($AuditDates as $auditdate) {
                                            $dates= $auditdate['Audit']['audit_date'];
                                            $date= date_format(date_create($dates), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';   
                                        }*/ /*by Swati T */
                                        foreach ($auditData['scheduledates'] as $value) {
                                            /*$msg2 .= '<td style="font-size: 18px; color: #fff;">';
                                            $msg2 .= '<strong> Date: </strong>'. $value . 
                                            '</td>';*/
                                            $date= date_format(date_create($value), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';
                                        } // Updated by Swati T

                                        /*Code modification done by swati T 04-12-2018 end*/
                                        $content .= $msg2 . '</td></tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> Location of Audit: </strong> ' . $auditData["Audit"]["audit_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> iComply Auditor Name: </strong> ' . $auditData["Audit"]["auditer_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> No. of Audit Days: </strong>' . $auditData["Audit"]["amount_of_days_audit"] . '
                                            </td>
                                        </tr>
                                    </table></td></tr></table>';

                            /*$content .= '<div style="page-break-after: always;"></div>';
                            $content .=  '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table border="0" cellpadding="0" cellspacing="0" width="" >
                                <tr>
                                    <td style="font-size: 20px; color: #000;">
                                        ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-size: 20px; color: #00b3ec;">
                                       ' . $auditData["Audit"]["client_name"] . '
                                    </td>
                                </tr>
                            </table>';*/
                            $content .= '<div style="page-break-after: always;"></div>';
                            $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:45px; color: #000; font-weight: bold">
                                    Thank you for letting us audit your awesome organization!!
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Audit Summary
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                    ' . $auditData["Audit"]["audit_summary"] . '
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Scope of audit
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                 ' . $auditData["Audit"]["audit_scope"] . '
                             </td>
                         </tr>
                     </table>
                     <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                        <tr>
                            <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                Standard(s)
                            </td>
                        </tr>
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                ' . $auditData["Audit"]["audit_standards"] . '
                            </td>
                        </tr>
                    </table>
                    ';
                    $content .= '<div style="page-break-after: always;"></div>';            
                    $content .='<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                    <tr>
                        <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                            Compliance Scores<br><br><br>
                        </td>                                   
                    </tr> 
                    <tr >
                       <td style="font-size:16px; color: #000; line-height:22px;">
                        Would a game ever become popular if there was no scoring? We love scoring. It can help an organization or department become laser focused on improvement.<br><br> Our scoring method is objective because it is based on evidence presented during the audit. <br><br> For greater insights, the auditor will also provide the Audit worksheets from this audit. The Audit Worksheet will let you see, line by line, which areas of your organization are complying or lacking.
                    </td>
                </tr>                             
            </table>
            <table border="0" cellpadding="0" cellspacing="0" width="100%" class="tbl-border-blackk" style="margin: 30px 0px;">
                <tr>
                    <th style="font-size: 16px; color: #fff; background-color:#00b3ec;text-transform: uppercase;">
                        Group Name
                    </th>
                    <th style="font-size: 16px; color: #fff;background-color:#00b3ec;text-transform: uppercase;">
                        Compliance Score (%)
                    </th>
                </tr>';
                $msg = '';
                if (!empty($auditData['complyScore1'])) {
                    foreach ($auditData['complyScore1'] as $value) {
                        // print_r($value);
                        $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000;">';
                        if ($value["percentage"] == "0") {
                            $value["percentage"] = '0';
                        }
                        if ($value["percentage"] == "-1" || $value["percentage"] == "-") {
                            $value["percentage"] = '-';
                        }
                        if (empty($value["percentage"])) {
                            $value["percentage"] = '';
                        }

                        //                    $msg .= $value["groupName1"] . '</td><td>' . $value["percentage"] . '</td><td>' . $value["end_time"];
                        $msg .= $value["groupName1"] ? $value["groupName1"] : "-" . '</td>';
                        $msg .= '<td style="font-size: 16px; color: #000;">'.$value["percentage"].'</td>';
                        $msg .= '</tr>';
                    }
                }



                $newCell = '';
                if(!empty($dataArr[0][0]['avgPercentage'])){
                    $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000; font-weight:bold; ">Average Compliance Score</td>';
                    if($dataArr[0][0]['avgPercentage'] == "-1" || $dataArr[0][0]['avgPercentage'] == "-" || $dataArr[0][0]['avgPercentage'] == ""){
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;"> - </td>';
                        //$msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? '-' : '-' . '</td></tr>';  
                    } else {
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;">'.round($dataArr[0][0]['avgPercentage'],2).'</td>';                        
                       // $msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? round($dataArr[0][0]['avgPercentage'], 2) : '-' . '</td></tr>';
                    } 
                }
                //$newCell .= "<td>test<td>";

                $msg .= $newCell."</tr>";
               //swatihere1
                $content .= $msg . '</table>';
                $content .= '<div style="page-break-after: always;"></div>'; 
                $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                <tr>
                    <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                        Audit Report<br><br><br>  
                    </td>
                </tr>
                <tr style="margin: 30px 0px;">
                    <td>
                        <p style="font-size:16px; color: #000; margin: 30px 0px;">
                            If you scored 100% at the end of the Compliance Scores table above, then there’s probably a good chance that this section is blank. Not to worry, it’s not a glitch in our reporting, it’s just that we could not find anything wrong, and that’s not a bad thing.<br><br>
                        </p>                            
                        <p style="font-size:16px; color: #000;">
                            And if there is anything reported in this section, hey, nobody’s perfect. Step back, gather your thoughts, take a deep breath, and GET YOUR GAME ON.<br><br>
                        </p>
                        <p style="font-size:16px; color: #000; margin: 30px 0px;">
                            By the way, the action code "NC" means non-conformance. A non-conformance either means you are not complying with your policies/procedures or the relevant standard.  If you receive an NC, your organization will need to correct the situation and start conforming. The action code "OB" means  Observation, or in other words a strong suggestion. You do not have to implement an observation, so we will leave that up to you to decide. Normally an observation is provided to help you improve.<br><br>
                        </p>
                        <p style="font-size:16px; color: #000;">
                            Here is your audit report…<br/><br/>
                        </p>
                    </td>
                </tr>
            </table>';
            $msg1 = '';
            $newMsg = '';
            $auditImage = '';
//                pr($auditData['complyScore']);
//                exit(__LINE__);
            $group_values = 1;
            foreach ($auditData['complyScore'] as $value) {             

                $msg1 = '';
                if($value['action_code'] != ''){
                    if(!empty($value["image"])){
                        $auditImage = '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0;" >
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                <img width="135" height="120" src="' . $value["image"].'" />
                            </td>
                        </tr>
                    </table>';  
                }else{
                    $auditImage='';
                }
                $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 8px 0px 0;">
                <tr>
                    <td style="text-align: center; font-weight: 600; font-size: 28px; color: #000">
                        Finding '.$group_values. '
                    </td>
                </tr>
            </table>';
            /*'.date('F j Y', strtotime($auditData["Audit"]["created_date"])).'*/ 
                                        //Commented by Swati T @04 Dec 2018
            $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin:  8px 0px 0;" >
            <tr>
                <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                    Action Code
                </td>
                <td style="font-size:16px; color: #000; text-align:left;">
                    ' . $value["action_code"] . '
                </td>
            </tr>
        </table>';
        $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
        <tr>    
            <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                Group name
            </td>
            <td style="font-size:16px; color: #000; text-align:left;">
                '.$value["groupName"].'
            </td>
        </tr>
    </table>';
    $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin:  8px 0px 0; width:100%;" >
    <tr>
        <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%;  vertical-align:top;">
            Audit Question
        </td>
        <td style="font-size:16px; color: #000; text-align:left;">
         ' . $value["audit_question"] . ' 
     </td>
 </tr>
</table>';
if($value["comment"]!=''){
    $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
    <tr>
        <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
            Finding
        </td>
        <td style="font-size:16px; color: #000; text-align:left;">
          ' . $value["comment"].'
      </td>
  </tr>
</table>'; 
}
$newMsg .= $auditImage;

$group_values++;
}
$msg1 .= $newMsg;

}
$content .= $msg1;

$content .= '<div style="page-break-after: always;"></div>';

$content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
<tr>
    <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
        Thank you.<br><br><br>
    </td>
</tr>
<tr>
    <td>
        <p style="font-size:16px; color: #000;">
           We love feedback, and yes, that also includes constructive criticism. If there is anything amiss or you are happy with this audit, and want you want to share it with us, please contact us:<br/><br/>
           Customer care:<br/><br>
           customercare@i-comply.co <br/>
           833 229 1215 <br/><br/>

           Please also consider completing a survey about your audit experience: <a href="https://www.surveymonkey.com/r/DTHGP9D"> https://www.surveymonkey.com/r/DTHGP9D </a>
           <br><br>
       </p>
   </td>
</tr>
</table>';

$content .= '<div style="page-break-after: always;"></div>';

$content .= '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
<table cellpadding="0" cellspacing="0" width="100%" border=0 style="margin: 30px 0px; ">
    <tr>
        <td rowspan="4" style="font-size: 18px; color: #fff;">
         <p> <strong>iComply </strong> <br>
             South Jordan, Utah <br>
             84095
         </td>
         <td style="font-size: 18px; color: #fff; text-align:center;">
            <p>i-comply.co.</p>
            <p>+1 833 229 1215</p>
        </td>
        <td>
            <img src="images/newlogo.png" alt="" style="width:100px">
        </td>
    </tr>
</table>';
$content .= '<htmlpagefooter name="MyFooter1">
<table width="100%" style="vertical-align: bottom; font-family: serif; font-size: 8pt; color: #000000; font-weight: bold; font-style: italic;">
    <tr>
        <td width="50%" align="left"><span style="font-weight: bold; font-style: italic; font-size:12px;">{DATE j-m-Y}</span></td>
        <td width="49%" align="right" style="font-weight: bold; font-style: italic;font-size:12px;">{PAGENO}/{nbpg}</td>
    </tr>
</table>
</htmlpagefooter>';

$content .= '</body>';   

ob_start();
error_reporting(0);
$mpdf = new mPDF('c', 'A4', '', '', 32, 25, 27, 25, 16, 13);
                $mpdf->writeHTML($content); // All result from database write here
                $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
                $senderEmail = DEFAULT_EMAIL_ADDRESS;
                $message = "Please click on below link <br>";
                $message.= "<a href=" . SITE_LINK . "/img/pdf_files/" . $pdfname . ">Download</a>";
                $subject = "audit report";
                if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message)) {
                    $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully');
                } else {
                    $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
                }
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'Data is not found');
            }
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Data is not in post format');
        }

        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function reportclientpdf_link() {
       configure::write('debug',0);
       $response = array();
       if ($this->request->isPost() && !empty($this->request->data)) {
        $audits_id = $this->request->data['audits_id'];
        $clients_id = $this->request->data['clients_id'];
        App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
        $this->loadModel('Audit');
        $this->loadModel('Client');
        $this->loadModel('Question');
        $this->loadModel('AuditGroupQuestionComments');
        $this->loadModel('AuditGroupComment');
        $this->loadModel('AuditGroupQuestion');


        $AuditDates = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.is_deleted' => 0), 'fields' => array('Audit.audit_date')));
        $scoreArr = array();
        $getArr = array();
        if ($clients_id != null && $audits_id != null) {
            $getArr = $this->AuditGroupQuestion->getAuditsQuestionsArr($clients_id, $audits_id);
        }

        if (!empty($getArr)) {
            $pdfname = "auditReportPdf" . time() . '.pdf';
            $i = 0;
            $contact_person_name = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.contact_person_name')));
            foreach ($getArr as $auditID) {
                $auditData['Audit'] = $auditID['Audit'];
                $companyName = $auditID['Client']['company_name'];
                $clients_id = $auditID['Audit']['clients_id'];
                if (!empty($clients_id)) {
                    $getClientDetail = $this->Client->find('first', array('conditions' => array('Client.id' => $clients_id)));
                    if (!empty($getClientDetail)) {
                        $clientDetail['client_email'] = $getClientDetail['Client']['email'];
                        $clientDetail['client_contact'] = $getClientDetail['Client']['contact_name'];
                        $clientDetail['client_contact_name'] = $getClientDetail['Client']['client_name'];
                        $clientDetail['phone_number'] = $getClientDetail['Client']['phone_number'];
                        $auditData['clientDtail'] = $clientDetail;
                    } else {
                        $auditData['clientDtail'] = array();
                    }
                }


                $dataArr[0][0]['avgPercentage'] = '100';

                if (!empty($auditID['AuditGroup'])) {
                    foreach ($auditID['AuditGroup'] as $val) {
                        $groupArrID[] = $val['groups_id'];
                        $getCompyNScore = $this->AuditGroupQuestionComments->getAllComplyScore($val['groups_id'], $audits_id, $clients_id);
                        $AuditGroupCommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.groups_id' => $val['groups_id'], 'AuditGroupComment.audits_id' => $audits_id, 'AuditGroupComment.clients_id' => $clients_id, 'AuditGroupComment.is_deleted' => 0, 'AuditGroupComment.action' => array('NC','OB')), 'fields' => array('AuditGroupComment.comment,AuditGroupComment.action,AuditGroupComment.image,AuditGroupComment.groups_id')));

//                            echo "\n\n";
//                            pr($getCompyNScore);
//                            echo "\n---------------------------------------------\n";
//                            pr($AuditGroupCommentArr);
//                            echo "<hr>";
//                            pr($this->AuditGroupComment->getDataSource()->getLog(0,0));

                        $question = "";
                        if (!empty($getCompyNScore)) {
                            foreach ($getCompyNScore as $getCompyNScoreArr) {
                                    //print_r($groupEndTime);
                                $queGrpID = !empty($getCompyNScoreArr['AuditGroupQuestionComments']['questions_id']) ? $getCompyNScoreArr['AuditGroupQuestionComments']['questions_id'] : 0;
                                $getQuestion = $this->Question->find('first', array('conditions' => array('Question.id' => $queGrpID)));

                                $question = !empty($getQuestion['Question']['question']) ? $getQuestion['Question']['question'] : "";
                                    $dataArr['auditsId']= $getCompyNScoreArr['AuditGroupQuestionComments']['audits_id']; // by swati t
                                    $dataArr['groupqueID']= $getCompyNScoreArr['AuditGroupQuestionComments']['id']; // by swati t
                                    $dataArr['audit_question'] = $getQuestion['Question']['question'];
                                    //$dataArr['percentage'] = $getCompyNScoreArr['AuditGroupQuestionComments']['percentage'];
                                    $dataArr['comment'] = $getCompyNScoreArr['AuditGroupQuestionComments']['comment'];
                                    $dataArr['created_date'] = $getCompyNScoreArr['AuditGroupQuestionComments']['created_date']; // by swati t
                                    $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image']; // by swati t

                                    $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image'];
                                    $dataArr['action_code'] = $getCompyNScoreArr['AuditGroupQuestionComments']['action'];
                                    $dataArr['groupName'] = $val['group_name'];
                                    
//                                        $dataArr['percentage'] = $groupEndTime['AuditGroupComment']['percentage'];
                                    //print_r($dataArr);
                                    $scoreArr[] = $dataArr;
                                }

                                $this->loadModel('AuditPercentage');
                                $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.audits_id' => $audits_id, 'AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage !=' => ''), 'fields' => array('AuditPercentage.end_time', 'AuditPercentage.percentage', 'AuditPercentage.groups_id'), 'order' => array('AuditPercentage.groups_id ASC')));
                                $dataArr = $this->AuditPercentage->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentage.clients_id' => $clients_id, 
                                    'AuditPercentage.audits_id' => $audits_id,
                                    "AuditPercentage.percentage NOT IN ('','-','-1',' ')"), 'group' => 'audits_id'));
                                ///*'AuditPercentage.percentage !=' => 0, */ //By Swati T @14Dec2018
                                $auditData['complyScore1'] = array();

                                foreach ($AuditPercentageArr as $AuditPercentageNewArr) {
                                    $groupInfo = $this->Audits->getAllGroupsByGroupId($AuditPercentageNewArr['AuditPercentage']['groups_id']);

                                    $dataArr1['percentage'] = $AuditPercentageNewArr['AuditPercentage']['percentage'];
                                    $dataArr1['end_time'] = $AuditPercentageNewArr['AuditPercentage']['end_time'];
                                    $dataArr1['groupName1'] = $groupInfo[0]['full_name'];
                                    $auditData['complyScore1'][] = $dataArr1;
                                }
                            }
                            if (!empty($AuditGroupCommentArr)) {
                                //print_r($AuditGroupCommentArr); exit;
                                //$scoreArrAudit = array();
                                foreach ($AuditGroupCommentArr as $AuditGroupCommentNewArr) {
                                    // $groupID= $AuditGroupCommentNewArr['AuditGroupComment']['groups_id'];
                                    //$groupName[0]['AuditGroup']['group_name'] = $this->AuditGroup->find('all',array('conditions'=>array('AuditGroup.groups_id'=>$groupID),'fields' => array('AuditGroup.group_name')));
                                    $dataArr['comment'] = $AuditGroupCommentNewArr['AuditGroupComment']['comment'];
                                    $dataArr['image'] = $AuditGroupCommentNewArr['AuditGroupComment']['image'];
                                    $dataArr['action_code'] = $AuditGroupCommentNewArr['AuditGroupComment']['action'];
                                    $dataArr['audit_question'] = "";
                                    $dataArr['groupName'] = $val['group_name'];
                                    $scoreArr[] = $dataArr;
                                }
                            }

                            $i++;
                        }
                        $auditData['complyScore'] = $scoreArr;
                    } else {
                        $auditData['complyScore'] = $scoreArr;
                    }
//                    echo '<br>'.__LINE__;
                    /*print_r($auditData['complyScore']);
                    echo "aaaaaaaaa";
                    print_r($auditID); 
                    exit;*/
                    $i++;
                    $scheduleDateArr = array();
                    if (!empty($auditID['AuditGroupSchedule'])) {
                        foreach ($auditID['AuditGroupSchedule'] as $val1) {
                            $schedulArr[] = $val1['schedule_date'];
                        }
                        $auditData['scheduledates'] = $schedulArr;
                    } else {
                        $auditData['scheduledates'] = array();
                    }
                }
                // echo "<pre/>";
                // print_r($auditData);
                // exit;
                
//        $this->autoRender=false;
//        $pdfName=$pdfname;   
                $content = '<style>               
                body, table, td, p, a, li, blockquote {
                    -webkit-text-size-adjust: none !important;
                    font-family: Arial;
                    color: #666;
                    font-size: 14px;
                }
                element.style {
                    font-size: 14px;
                }
                *::after, *::before {
                box-sizing: border-box;
            }
                *::after, *::before {
            box-sizing: border-box;
        }
        b, strong {
            font-weight: 700;
        }
                * {
        box-sizing: border-box;
    }
    label {
        cursor: default;
    }
    body {
        font-family: "Open Sans",sans-serif;
        line-height: 1.42857;
        font-size: 14px;
        line-height: 1.42857;
    }
                *::after, *::before {
    box-sizing: border-box;
}
                *::after, *::before {
box-sizing: border-box;
}
.mar-0-auto{
    margin: 0 auto;
}
.tbl-border-white{
    border: 1px solid #fff
}
.tbl-border-white td, .tbl-border-white th{
    border: 1px solid #fff;
    padding: 10px;
}
.tbl-border-black{
    border: 1px solid #fff;
}
.tbl-border-black td, .tbl-border-black th{
    border: 1px solid #333;
    padding: 10px;
}
.tbl-border-blackk td, .tbl-border-blackk th{
    border: 1px solid #fff;
    border-bottom-width:3px;
    padding: 10px;
}
@page :first{
    background: #00b3ec;
}
@page :last{
    background: #00b3ec;
}
@page {
  size: auto;
  odd-header-name: html_MyHeader1;
  odd-footer-name: html_MyFooter1;
}
</style>
<body>
    <table border="0" cellpadding="0" cellspacing="0" width="100%" class="mar-0-auto">
        <tr>
            <td>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td>
                            <img src="images/logo_new.png" alt="">
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 32px; color: #000; font-weight: 600">
                            Audit Report for
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 70px; color: #fff; font-weight: 600; text-transform: uppercase">
                            '.$companyName.'
                        </td>
                    </tr>
                </table><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
                <table cellpadding="0" cellspacing="0" width="100%" class="tbl-border-white" style="margin: 30px 0px; ">
                    <tr>
                        <td rowspan="4" style="font-size: 18px; color: #fff;">
                            <strong> Prepared for:</strong><br/>
                            ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '<br/>
                            ' . $auditData["Audit"]["client_name"] . '<br/>
                            ' . $auditData["clientDtail"]["phone_number"] . '<br>
                            ' . $auditData["clientDtail"]["client_email"] . '
                        </td>';
                        /*Code modification done by swati T 04-12-2018 start*/
                        $msg2 = '';                                        
                        $msg2 .= '<td style="font-size: 18px; color: #fff;">';
                        $msg2 .= '<strong> Dates: </strong><br/>'; 
                                        /*foreach ($AuditDates as $auditdate) {
                                            $dates= $auditdate['Audit']['audit_date'];
                                            $date= date_format(date_create($dates), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';   
                                        }*/ /*by Swati T */

                                        foreach ($auditData['scheduledates'] as $value) {
                                            /*$msg2 .= '<td style="font-size: 18px; color: #fff;">';
                                            $msg2 .= '<strong> Date: </strong>'. $value . 
                                            '</td>';*/
                                            $date= date_format(date_create($value), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';
                                        } // Updated by Swati T

                                        /*Code modification done by swati T 04-12-2018 end*/
                                        $content .= $msg2 . '</td></tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> Location of Audit: </strong> ' . $auditData["Audit"]["audit_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> iComply Auditor Name: </strong> ' . $auditData["Audit"]["auditer_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> No. of Audit Days: </strong>' . $auditData["Audit"]["amount_of_days_audit"] . '
                                            </td>
                                        </tr>
                                    </table></td></tr></table>';

                            /*$content .= '<div style="page-break-after: always;"></div>';
                            $content .=  '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table border="0" cellpadding="0" cellspacing="0" width="" >
                                <tr>
                                    <td style="font-size: 20px; color: #000;">
                                        ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-size: 20px; color: #00b3ec;">
                                       ' . $auditData["Audit"]["client_name"] . '
                                    </td>
                                </tr>
                            </table>';*/
                            $content .= '<div style="page-break-after: always;"></div>';
                            $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:45px; color: #000; font-weight: bold">
                                    Thank you for letting us audit your awesome organization!!
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Audit Summary
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                    ' . $auditData["Audit"]["audit_summary"] . '
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Scope of audit
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                 ' . $auditData["Audit"]["audit_scope"] . '
                             </td>
                         </tr>
                     </table>
                     <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                        <tr>
                            <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                Standard(s)
                            </td>
                        </tr>
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                ' . $auditData["Audit"]["audit_standards"] . '
                            </td>
                        </tr>
                    </table>
                    ';
                    $content .= '<div style="page-break-after: always;"></div>';            
                    $content .='<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                    <tr>
                        <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                            Compliance Scores<br><br><br>
                        </td>                                   
                    </tr> 
                    <tr >
                       <td style="font-size:16px; color: #000; line-height:22px;">
                        Would a game ever become popular if there was no scoring? We love scoring. It can help an organization or department become laser focused on improvement.<br><br> Our scoring method is objective because it is based on evidence presented during the audit. <br><br> For greater insights, the auditor will also provide the Audit worksheets from this audit. The Audit Worksheet will let you see, line by line, which areas of your organization are complying or lacking.
                    </td>
                </tr>                             
            </table>
            <table border="0" cellpadding="0" cellspacing="0" width="100%" class="tbl-border-blackk" style="margin: 30px 0px;">
                <tr>
                    <th style="font-size: 16px; color: #fff; background-color:#00b3ec;text-transform: uppercase;">
                        Group Name
                    </th>
                    <th style="font-size: 16px; color: #fff;background-color:#00b3ec;text-transform: uppercase;">
                        Compliance Score (%)
                    </th>
                </tr>';
                $msg = '';
                if (!empty($auditData['complyScore1'])) {
                    foreach ($auditData['complyScore1'] as $value) {
                        // print_r($value);
                        $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000;">';
                        if ($value["percentage"] == "0") {
                            $value["percentage"] = '0';
                        }
                        if ($value["percentage"] == "-1" || $value["percentage"] == "-") {
                            $value["percentage"] = '-';
                        }
                        if ($value["percentage"] == "") {
                            $value["percentage"] = '';
                        }
                        //                    $msg .= $value["groupName1"] . '</td><td>' . $value["percentage"] . '</td><td>' . $value["end_time"];
                        $msg .= $value["groupName1"] ? $value["groupName1"] : "-" . '</td>';
                        $msg .= '<td style="font-size: 16px; color: #000;">'.$value["percentage"].'</td>';
                        $msg .= '</tr>';
                    }
                }

                $newCell = '';
                if(!empty($dataArr[0][0]['avgPercentage'])){
                    $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000; font-weight:bold; ">Average Compliance Score</td>';
                    if($dataArr[0][0]['avgPercentage'] == "-1" || $dataArr[0][0]['avgPercentage'] == "-" || $dataArr[0][0]['avgPercentage'] == ""){
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;"> - </td>';
                        //$msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? '-' : '-' . '</td></tr>';  
                    } else {
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;">'.round($dataArr[0][0]['avgPercentage'],2).'</td>';                            
                       // $msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? round($dataArr[0][0]['avgPercentage'], 2) : '-' . '</td></tr>';
                    } 
                }
                //$newCell .= "<td>test<td>";

                $msg .= $newCell."</tr>";
               //swatihere
                $content .= $msg . '</table>';
                $content .= '<div style="page-break-after: always;"></div>'; 
                $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                <tr>
                    <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                        Audit Report<br><br><br> 
                    </td>
                </tr>
                <tr style="margin: 30px 0px;">
                    <td>
                        <p style="font-size:16px; color: #000; margin: 30px 0px;">
                            If you scored 100% at the end of the Compliance Scores table above, then there’s probably a good chance that this section is blank. Not to worry, it’s not a glitch in our reporting, it’s just that we could not find anything wrong, and that’s not a bad thing.<br><br>
                        </p>                            
                        <p style="font-size:16px; color: #000;">
                            And if there is anything reported in this section, hey, nobody’s perfect. Step back, gather your thoughts, take a deep breath, and GET YOUR GAME ON.<br><br>
                        </p>
                        <p style="font-size:16px; color: #000; margin: 30px 0px;">
                            By the way, the action code "NC" means non-conformance. A non-conformance either means you are not complying with your policies/procedures or the relevant standard.  If you receive an NC, your organization will need to correct the situation and start conforming. The action code "OB" means  Observation, or in other words a strong suggestion. You do not have to implement an observation, so we will leave that up to you to decide. Normally an observation is provided to help you improve.<br><br>
                        </p>
                        <p style="font-size:16px; color: #000;">
                            Here is your audit report…<br/><br/>
                        </p>
                    </td>
                </tr>
            </table>';
            $msg1 = '';
            $newMsg = '';
            $auditImage = '';
//                pr($auditData['complyScore']);
//                exit(__LINE__);
            $group_values = 1;

            foreach ($auditData['complyScore'] as $value) {                   
                $msg1 = '';
                if($value['action_code'] != ''){
                    if(!empty($value["image"])){
                        $auditImage = '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0;" >
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                <img width="135" height="120" src="' . $value["image"].'" />
                            </td>
                        </tr>
                    </table>';  
                }else{
                    $auditImage='';
                }
                $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 8px 0px 0;">
                <tr>
                    <td style="text-align: center; font-weight: 600; font-size: 28px; color: #000">
                        Finding '.$group_values. '
                    </td>
                </tr>
            </table>';
                                        /*'.date('F j Y', strtotime($auditData["Audit"]["created_date"])).'*/ //Commented by Swati T @04 Dec 2018
                                        $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin:  8px 0px 0;" >
                                        <tr>
                                            <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                                Action Code
                                            </td>
                                            <td style="font-size:16px; color: #000; text-align:left;">
                                                ' . $value["action_code"] . '
                                            </td>
                                        </tr>
                                    </table>';
                                    $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
                                    <tr>    
                                        <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                            Group name
                                        </td>
                                        <td style="font-size:16px; color: #000; text-align:left;">
                                            '.$value["groupName"].'
                                        </td>
                                    </tr>
                                </table>';
                                $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin:  8px 0px 0; width:100%;" >
                                <tr>
                                    <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%;  vertical-align:top;">
                                        Audit Question
                                    </td>
                                    <td style="font-size:16px; color: #000; text-align:left;">
                                     ' . $value["audit_question"] . ' 
                                 </td>
                             </tr>
                         </table>';
                         if($value["comment"]!=''){
                            $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
                            <tr>
                                <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                    Finding
                                </td>
                                <td style="font-size:16px; color: #000; text-align:left;">
                                  ' . $value["comment"].'
                              </td>
                          </tr>
                      </table>'; 
                  }
                  $newMsg .= $auditImage;
                  $group_values++;
              }
              $msg1 .= $newMsg;

          }
          $content .= $msg1;

          $content .= '<div style="page-break-after: always;"></div>';

          $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
          <tr>
            <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                Thank you.<br><br><br>
            </td>
        </tr>
        <tr>
            <td>
                <p style="font-size:16px; color: #000;">
                   We love feedback, and yes, that also includes constructive criticism. If there is anything amiss or you are happy with this audit, and want you want to share it with us, please contact us:<br/><br/>
                   Customer care:<br/><br>
                   customercare@i-comply.co <br/>
                   833 229 1215 <br/><br/>

                   Please also consider completing a survey about your audit experience: <a herf="https://www.surveymonkey.com/r/DTHGP9D" target="_blank"> https://www.surveymonkey.com/r/DTHGP9D.</a>
                   <br><br>
               </p>
           </td>
       </tr>
   </table>';

   $content .= '<div style="page-break-after: always;"></div>';

   $content .= '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
   <table cellpadding="0" cellspacing="0" width="100%" border=0 style="margin: 30px 0px; ">
    <tr>
        <td rowspan="4" style="font-size: 18px; color: #fff;">
         <p> <strong>iComply </strong> <br>
             South Jordan, Utah <br>
             84095
         </td>
         <td style="font-size: 18px; color: #fff; text-align:center;">
            <p>i-comply.co</p>
            <p>+1 833 229 1215</p>
        </td>
        <td>
            <img src="images/newlogo.png" alt="" style="width:100px">
        </td>
    </tr>
</table>';
$content .= '<htmlpagefooter name="MyFooter1">
<table width="100%" style="vertical-align: bottom; font-family: serif; font-size: 8pt; color: #000000; font-weight: bold; font-style: italic;">
    <tr>
        <td width="50%" align="left"><span style="font-weight: bold; font-style: italic; font-size:12px;">{DATE j-m-Y}</span></td>
        <td width="49%" align="right" style="font-weight: bold; font-style: italic;font-size:12px;">{PAGENO}/{nbpg}</td>
    </tr>
</table>
</htmlpagefooter>';

$content .= '</body>';                 

$mpdf = new mPDF('c', 'A4', '', '', 32, 25, 27, 25, 16, 13);
                $mpdf->writeHTML($content, 0); // All result from database write here
                //$mpdf->AddPage('','','','','','','','','','','','html_MyHeader2', '', 'html_MyFooter2', '', 0, 0, 0, 0);
                $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
                $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;

                /***************************

                $mpdf = new mPDF('c', 'A4', '', '', 32, 25, 27, 25, 16, 13);

                // Set a simple Footer including the page number
                //$mpdf->setFooter('{PAGENO}');

                $mpdf->WriteHTML($content);

                // You could also do this using
                $mpdf->AddPage('','','','','on');

                //$mpdf->Output();
                ********************************/

                $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
                $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;                

                if ($msg) {
                    $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => $msg);
                } else {
                    $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
                }
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'Data is not found');
            }
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function barChartPdf() {
        // Configure::write('debug', 2);
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $this->loadModel('AuditGroupQuestionComments');
            $clientID = $this->request->data['clients_id'];
            // include this line when in trouble in option variable as parameter
            // , 'AuditGroupQuestionComments.action' => 'Comply'
            $options = array('conditions' => array('AuditGroupQuestionComments.clients_id' => $clientID), 'order' => array('YEAR(AuditGroupQuestionComments.created_date)' => 'asc'));
            $dataArr = $this->AuditGroupQuestionComments->find('all', $options);

            $complyPercentage = 0;
            if (!empty($dataArr)) {
                foreach ($dataArr as $val) {
                    $fields['year'][] = date('Y', strtotime($val['AuditGroupQuestionComments']['created_date']));
                }
                $uniqueYear = array();
                $uniqueYear = array_unique($fields['year']);

                $finalresult = array();
                $finalArr = array();
                foreach ($uniqueYear as $val) {
                    $i = 0;
                    $newcount = 0;
                    $complyPercentage = 0;
                    $finalresult = array();
                    foreach ($dataArr as $val1) {
                        $year = date('Y', strtotime($val1['AuditGroupQuestionComments']['created_date']));
                        if ($val == $year) {
                            if ($i == 0) {
                                $count = 0;
                            } else {
                                $count = $newcount;
                            }
                            $complyPercentage = $complyPercentage + $val1['AuditGroupQuestionComments']['percentage'];
                            $finalresult['year'] = $year;
                            //  $finalresult['percentage']=$count + 1;
                            $totalcount = $count + 1;
                            $newcount = $totalcount;
                            $i++;
                        }
                    }
                    $finalresult['percentage'] = $complyPercentage / $newcount;
                    $finalArr[] = $finalresult;
                }
                
                $this->management = new ManagementsController();
                $val = $this->management->admin_testdemopdf($clientID);

                if ($val == BOOL_TRUE) {
                    $response = array('status' => '1', 'data' => 'Highchart generated successfully', 'message' => 'Highchart generated successfully');
                } else {
                    $response = array('status' => '0', 'message' => 'Failure');
                }
            } else {
                $response = array('status' => '0', 'message' => 'Not found ', 'data' => array());
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format');
        }

        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    function sorterByGroupNampe($key) {
        return function ($a, $b) use ($key) {
            return strnatcmp($a[$key], $b[$key]);
        };
    }

    function sortByCreatedDate($key) {
        return function ($a, $b) use ($key) {
            return strtotime($a) - strtotime($b);
        };
    }

    public function getActionChecklist() {
        Configure::write('debug',0);
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $clients_id = $this->request->data['clients_id'];
            $this->loadModel('AuditGroupQuestionComments');
            $this->loadModel('AuditGroupComments');
            $this->loadModel('AuditGroup');
            $this->loadModel('Question');
            $this->loadModel('Audit');
            $getactionlist = $this->AuditGroupQuestionComments->find('all', array( 'order' => array('AuditGroupQuestionComments.id'=>'desc'), 'conditions' => array('AuditGroupQuestionComments.clients_id' => $clients_id, 'AuditGroupQuestionComments.action' => array('NC', 'OB')), 'fields' => array('AuditGroupQuestionComments.id', 'AuditGroupQuestionComments.action_to_be_taken', 'AuditGroupQuestionComments.comment', 'AuditGroupQuestionComments.action', 'AuditGroupQuestionComments.audits_id', 'AuditGroupQuestionComments.groups_id', 'AuditGroupQuestionComments.clients_id', 'AuditGroupQuestionComments.questions_id', 'AuditGroupQuestionComments.image', 'AuditGroupQuestionComments.action', 'AuditGroupQuestionComments.percentage', 'AuditGroupQuestionComments.post_action_comments', 'AuditGroupQuestionComments.completed', 'AuditGroupQuestionComments.date_completed', 'AuditGroupQuestionComments.created_date')));
            $getComments = $this->AuditGroupComments->getAllComments($clients_id);
//          print_r($getComments);           
            if (!empty($getComments)) {
                foreach ($getComments as $getCommentsArr) {
                    $group_id = $getCommentsArr['AuditGroupComments']['groups_id'];
                    $questions_id = !empty($getCommentsArr['AuditGroupComments']['questions_id']) ? $getCommentsArr['AuditGroupComments']['questions_id'] : '';
                    $audits_id = $getCommentsArr['AuditGroupComments']['audits_id'];
                    $groupName = $this->AuditGroup->find('all', array('conditions' => array('AuditGroup.groups_id' => $group_id)));
                    $getAudit = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id, 'Audit.is_deleted' => 0)));
                    if (!empty($getAudit)) {
                        $CommentsArr['audit_name'] = $getAudit[0]['Audit']['audit_name'];
                        $CommentsArr['created_date'] = $getAudit[0]['Audit']['created_date'];
                        $CommentsArr['group_name'] = $groupName[0]['AuditGroup']['group_name'];
                        $CommentsArr['group_audit_id'] = $groupName[0]['AuditGroup']['id'];
                        $CommentsArr['question'] = '';
                        $CommentsArr['id'] = $getCommentsArr['AuditGroupComments']['id'];
                        $CommentsArr['action'] = $getCommentsArr['AuditGroupComments']['action'];
                        $CommentsArr['comment'] = $getCommentsArr['AuditGroupComments']['comment'];
                        $CommentsArr['image'] = !empty($getCommentsArr['AuditGroupComments']['image']) ? $getCommentsArr['AuditGroupComments']['image'] : '';
                        $CommentsArr['action_to_be_taken'] = $getCommentsArr['AuditGroupComments']['action_to_be_taken'];
                        $CommentsArr['post_action_comments'] = $getCommentsArr['AuditGroupComments']['post_action_comments'];
                        $CommentsArr['completed'] = $getCommentsArr['AuditGroupComments']['completed'];
                        if ($getCommentsArr['AuditGroupComments']['date_completed'] == "0000-00-00") {
                            $CommentsArr['date_completed'] = "";
                        } else {
                            $CommentsArr['date_completed'] = $getCommentsArr['AuditGroupComments']['date_completed'];
                        }
                        $CommentsArr['comenttype'] = "grp";

                        $scoreArr[] = $CommentsArr;
                    }
                }
            }
            if (!empty($getactionlist)) {
                foreach ($getactionlist as $getactionlistArr) {
//                    echo "\n";
                    $group_id = $getactionlistArr['AuditGroupQuestionComments']['groups_id'];
                    $questions_id = $getactionlistArr['AuditGroupQuestionComments']['questions_id'];
                    $audits_id = $getactionlistArr['AuditGroupQuestionComments']['audits_id'];
                    $groupName = $this->AuditGroup->find('all', array('conditions' => array('AuditGroup.groups_id' => $group_id)));
                    $getQuestion = $this->Question->find('all', array('conditions' => array('Question.id' => $questions_id)));

                    //print_r($audits_id);
                    $getAudit = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id, 'Audit.is_deleted' => 0)));

                    if (!empty($getAudit)) {
                        $actionlistArr['audit_name'] = $getAudit[0]['Audit']['audit_name'];
                        $actionlistArr['created_date'] = $getAudit[0]['Audit']['created_date'];
                        $actionlistArr['group_name'] = $groupName[0]['AuditGroup']['group_name'];
                        $actionlistArr['group_audit_id'] = $groupName[0]['AuditGroup']['id'];
                        $actionlistArr['question'] = $getQuestion[0]['Question']['question'];
                        $actionlistArr['id'] = $getactionlistArr['AuditGroupQuestionComments']['id'];
                        $actionlistArr['action'] = $getactionlistArr['AuditGroupQuestionComments']['action'];
                        $actionlistArr['comment'] = $getactionlistArr['AuditGroupQuestionComments']['comment'];
                        $actionlistArr['image'] = $getactionlistArr['AuditGroupQuestionComments']['image'];
                        $actionlistArr['action_to_be_taken'] = $getactionlistArr['AuditGroupQuestionComments']['action_to_be_taken'];
                        $actionlistArr['post_action_comments'] = $getactionlistArr['AuditGroupQuestionComments']['post_action_comments'];
                        $actionlistArr['completed'] = $getactionlistArr['AuditGroupQuestionComments']['completed'];
                        if ($getactionlistArr['AuditGroupQuestionComments']['date_completed'] == "0000-00-00") {
                            $actionlistArr['date_completed'] = "";
                        } else {
                            $actionlistArr['date_completed'] = $getactionlistArr['AuditGroupQuestionComments']['date_completed'];
                        }
                        $actionlistArr['comenttype'] = "que";
                        //print_r($actionlistArr);
                        $scoreArr[] = $actionlistArr;
                    }
                }
            }

//            pr($this->AuditGroupQuestionComments->getDataSource()->getLog(0,0));
// Sorting by group name and build_sorter this function for sorting....
            usort($scoreArr, $this->sorterByGroupNampe('group_name'));

            if (isset($scoreArr) && !empty($scoreArr)) {
//            $response = array('status' => '1', 'message' => 'Action checklist found','data'=>$actionlistArr);
                $response = array('status' => '1', 'message' => 'Action checklist found', 'data' => $scoreArr);
            } else {
                $response = array('status' => '0', 'message' => 'Action checklist not found', 'data' => 'Action checklist not found');
            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format', 'data' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function updateActionChecklist() {
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);
        $response = array();
        $this->loadModel('Audit');
        $this->loadModel('Question');
        $this->loadModel('AuditGroup');
        $this->loadModel('AuditGroupComments');
        $this->loadModel('AuditGroupQuestionComments');
        if (isset($input_data) && !empty($input_data)) {
            //foreach($input_data as $data){
            //print_r($data);
            //$getactionlist = $this->AuditGroupQuestionComments->find('all',array('conditions'=>array('AuditGroupQuestionComments.id'=>$data['id'])));
            //            print_r($group_id);print_r($questions_id);print_r($audit_id);

            if ($input_data['comenttype'] === 'grp') {
                $id = $input_data['id'];
                $auditArr['action_to_be_taken'] = "'{$input_data['action_to_be_taken']}'";
                $auditArr['post_action_comments'] = "'{$input_data['post_action_comments']}'";
                $auditArr['completed'] = "'{$input_data['completed']}'";
                $auditArr['date_completed'] = "'{$input_data['date_completed']}'";
                $conditions = array('AuditGroupComments.id' => $id);
                if ($this->AuditGroupComments->updateAll($auditArr, $conditions)) {
                    $response = array('status' => '1', 'message' => 'record updated sucessfully.');
                } else {
                    $response = array('status' => '0', 'message' => 'problem in updating record');
                }
            } elseif ($input_data['comenttype'] === 'que') {
                $id = $input_data['id'];
                $auditArr['action_to_be_taken'] = "'{$input_data['action_to_be_taken']}'";
                $auditArr['post_action_comments'] = "'{$input_data['post_action_comments']}'";
                $auditArr['completed'] = "'{$input_data['completed']}'";
                $auditArr['date_completed'] = "'{$input_data['date_completed']}'";
                $conditions = array('AuditGroupQuestionComments.id' => $id);
                if ($this->AuditGroupQuestionComments->updateAll($auditArr, $conditions)) {
                    $response = array('status' => '1', 'data' => 'record updated sucessfully.', 'message' => 'record updated sucessfully.');
                } else {
                    $response = array('status' => '0', 'message' => 'problem in updating record');
                }
            }

//            }
        } else {
            $response = array('status' => '0', 'message' => 'Data is not in post format',);
        }

        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function actionChecklistpdf() {
        Configure::write('debug',0);
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $clients_id = $this->request->data['clients_id'];
            $email = $this->request->data['email'];
            App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
            $this->loadModel('AuditGroupQuestionComments');
            $this->loadModel('AuditGroupComments');
            $this->loadModel('AuditGroup');
            $this->loadModel('Question');
            $this->loadModel('Audit');
            $order = array('AuditGroupQuestionComments.created_date' => 'DESC');
            $getactionlist = $this->AuditGroupQuestionComments->find('all', array('conditions' => array('AuditGroupQuestionComments.clients_id' => $clients_id, 'AuditGroupQuestionComments.action' => array('NC', 'OB')),'Order'=>array('AuditGroupQuestionComments.id'=>'DESC'), 'fields' => array('AuditGroupQuestionComments.id', 'AuditGroupQuestionComments.action_to_be_taken', 'AuditGroupQuestionComments.comment', 'AuditGroupQuestionComments.action', 'AuditGroupQuestionComments.audits_id', 'AuditGroupQuestionComments.groups_id', 'AuditGroupQuestionComments.clients_id', 'AuditGroupQuestionComments.questions_id', 'AuditGroupQuestionComments.image', 'AuditGroupQuestionComments.action', 'AuditGroupQuestionComments.percentage', 'AuditGroupQuestionComments.post_action_comments', 'AuditGroupQuestionComments.completed', 'AuditGroupQuestionComments.date_completed', 'AuditGroupQuestionComments.created_date')));
            //$getactionlist = $this->AuditGroupQuestionComments->find('all',array('conditions'=>array('AuditGroupQuestionComments.clients_id'=>$clients_id,'AuditGroupQuestionComments.action' => array('Non-conformance', 'Observation')),'Order'=>array('Audit.audit_name'=>'ASC')));
            //$getactionlist = $this->AuditGroupQuestionComments->find('all',array('recursive'=> -1,'fields'=>array('AuditGroupQuestionComments.id')));
            $getComments = $this->AuditGroupComments->getAllComments($clients_id);
            if (!empty($getComments)) {
                foreach ($getComments as $getCommentsArr) {
                    $group_id = $getCommentsArr['AuditGroupComments']['groups_id'];
                    //$questions_id = $getCommentsArr['AuditGroupComments']['questions_id'];
                    $questions_id = !empty($getCommentsArr['AuditGroupComments']['questions_id']) ? $getCommentsArr['AuditGroupComments']['questions_id'] : '';
                    $audits_id = $getCommentsArr['AuditGroupComments']['audits_id'];
                    $groupName = $this->AuditGroup->find('all', array('conditions' => array('AuditGroup.groups_id' => $group_id)));
                    //$order = array('Audit.created_date' => 'ASC');
                    $getAudit = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id, 'Audit.is_deleted' => 0)));
                    //print_r($getAudit); exit;
                    if (!empty($getAudit)) {
                        $CommentsArr['audit_name'] = $getAudit[0]['Audit']['audit_name'];
                        $CommentsArr['created_date'] = $getAudit[0]['Audit']['created_date'];
                        $CommentsArr['group_name'] = $groupName[0]['AuditGroup']['group_name'];
                        $CommentsArr['question'] = '';
                        $CommentsArr['id'] = $getCommentsArr['AuditGroupComments']['id'];
                        $CommentsArr['action'] = $getCommentsArr['AuditGroupComments']['action'];
                        $CommentsArr['comment'] = $getCommentsArr['AuditGroupComments']['comment'];
                        $CommentsArr['image'] = '';
                        $CommentsArr['action_to_be_taken'] = '';
                        $CommentsArr['post_action_comments'] = '';
                        $CommentsArr['completed'] = '';
                        $CommentsArr['date_completed'] = "";

                        $scoreArr[] = $CommentsArr;
                    }
                }
            }

            if (!empty($getactionlist)) {
                foreach ($getactionlist as $getactionlistArr) {
                    $group_id = $getactionlistArr['AuditGroupQuestionComments']['groups_id'];
                    $questions_id = $getactionlistArr['AuditGroupQuestionComments']['questions_id'];
                    $audits_id = $getactionlistArr['AuditGroupQuestionComments']['audits_id'];
                    $groupName = $this->AuditGroup->find('all', array('conditions' => array('AuditGroup.groups_id' => $group_id)));
                    $getQuestion = $this->Question->find('all', array('conditions' => array('Question.id' => $questions_id)));
                    //$order = array('Audit.created_date' => 'DESC');
                    $getAudit = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id, 'Audit.is_deleted' => 0)));
                    //print_r($getAudit); exit;
                    if (!empty($getAudit)) {
                        $actionlistArr['audit_name'] = $getAudit[0]['Audit']['audit_name'];
                        $actionlistArr['created_date'] = $getAudit[0]['Audit']['created_date'];
                        $actionlistArr['group_name'] = $groupName[0]['AuditGroup']['group_name'];
                        $actionlistArr['question'] = $getQuestion[0]['Question']['question'];
                        $actionlistArr['action'] = $getactionlistArr['AuditGroupQuestionComments']['action'];
                        //$actionlistArr['action'] = $getactionlistArr['AuditGroupQuestionComments']['action'];
                        $actionlistArr['comment'] = $getactionlistArr['AuditGroupQuestionComments']['comment'];
                        $actionlistArr['image'] = $getactionlistArr['AuditGroupQuestionComments']['image'];
                        $actionlistArr['action_to_be_taken'] = $getactionlistArr['AuditGroupQuestionComments']['action_to_be_taken'];
                        $actionlistArr['post_action_comments'] = $getactionlistArr['AuditGroupQuestionComments']['post_action_comments'];
                        $actionlistArr['completed'] = $getactionlistArr['AuditGroupQuestionComments']['completed'];
                        if ($getactionlistArr['AuditGroupQuestionComments']['date_completed'] == "0000-00-00") {
                            $actionlistArr['date_completed'] = "";
                        } else {
                            $actionlistArr['date_completed'] = $getactionlistArr['AuditGroupQuestionComments']['date_completed'];
                        }
                        $scoreArr[] = $actionlistArr;
                    }
                }
            }
            
            // Sorting by group name and build_sorter this function for sorting....
            usort($scoreArr, $this->sorterByGroupNampe('group_name'));
            //usort($scoreArr, $this->sortByCreatedDate('created_date'));
            //print_r($scoreArr); exit;
            if (isset($scoreArr) && !empty($scoreArr)) {
                $pdfname = "actionChecklistPdf" . time().".pdf";
                $content = '<img src="../img/logo.png" style="background:black">
                <br></br><br></br>
                <table border="1">
                            <tbody><tr><th>Location</th><th>Date</th><th>Group Name</th><th>Audit Question</th><th>Action Code</th><th>Comments</th><th>Action to be taken</th><th>Post Action Comments</th><th>Date Complete</th></tr>'; //<th>Completed</th>
                                $msg1 = '';

                                foreach ($scoreArr as $value) {
                                    $collectArr[] = date('Y', strtotime($value["created_date"]));
                                }
                                $result= array_unique($collectArr);
                                $arrCount= count($result);

                                foreach ($scoreArr as $value) {
                                    $year= date('Y', strtotime($value["created_date"]));

                                    if($year==date('Y')){
                                        $msg1 .= '<tr><td>';
                                        $msg1 .= $value["audit_name"] . '</td><td>' . date('F j Y', strtotime($value["created_date"])) . '</td><td>' . $value["group_name"] . '</td><td>' . $value["question"] . '</td><td>' . $value["action"] . '</td><td>' . $value["comment"] . '</td><td>' . $value["action_to_be_taken"] . '</td><td>' . $value["post_action_comments"] . '</td><td>' . $value["date_completed"];
                        $msg1 .= '</td></tr>'; //<td>' . $value["completed"] . '</td>
                    }
                    if($year== date("Y")-1){
                        $msg2 .= '<tr><td>';
                        $msg2 .= $value["audit_name"] . '</td><td>' . date('F j Y', strtotime($value["created_date"])) . '</td><td>' . $value["group_name"] . '</td><td>' . $value["question"] . '</td><td>' . $value["action"] . '</td><td>' . $value["comment"] . '</td><td>' . $value["action_to_be_taken"] . '</td><td>' . $value["post_action_comments"] . '</td><td>' . $value["date_completed"];
                        $msg2 .= '</td></tr>'; //<td>' . $value["completed"] . '</td>     
                    }
                    if($year== date("Y")-2){
                        $msg2 .= '<tr><td>';
                        $msg2 .= $value["audit_name"] . '</td><td>' . date('F j Y', strtotime($value["created_date"])) . '</td><td>' . $value["group_name"] . '</td><td>' . $value["question"] . '</td><td>' . $value["action"] . '</td><td>' . $value["comment"] . '</td><td>' . $value["action_to_be_taken"] . '</td><td>' . $value["post_action_comments"] . '</td><td>' . $value["date_completed"];
                        $msg2 .= '</td></tr>'; //<td>' . $value["completed"] . '</td>     
                    }

                }

                $msg2.=$msg3;
                $msg1.=$msg2;
                
                $content .= $msg1 . '</tbody></table>
                <p>&nbsp;</p>
                ';
                // $mpdf = new mPDF('c', 'A4', '', '', 32, 25, 27, 25, 16, 13);
                // $mpdf = new mPDF('', 'Letter', 0, '', 12.7, 12.7, 14, 12.7, 8, 8);  'A4-L',
                $mpdf = new mPDF('c','A4-L', 0, '', 10, 10, 14, 10, 8, 8);
                $mpdf->writeHTML($content);
                $mpdf->SetDisplayMode('fullpage'); // All result from database write here
                $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
                $attachment = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname;
                $senderEmail = DEFAULT_EMAIL_ADDRESS;
                $message = "Please find the attachment <br>";
                // $message.= "<a href=" . Router::fullbaseUrl() . "/admin/managements/downloadPDF/" . $pdfname . ">Download</a>";
                
                $subject = "action checklist";
                //$cc = 'madhuri@yopmail.com';



               
                if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachment)) {
                    //print_r($message);exit;
                    $response = array('status' => BOOL_TRUE, 'data' => 'Email sent successfully.', 'message' => 'Email sent successfully');
                } else {
                    $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
                }
            } else {
                $response = array('status' => '0', 'message' => 'Data is not in post format');
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }

    public function auditGroupExtraInfo() {
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $group_id = $this->request->data['groups_id'];
            $groupData = $this->Audits->getAllGroupsByGroupId($group_id);
            if (isset($groupData)) {
                $groupInfo['audit_defination'] = $groupData[0]['audit_defination'];
                $groupInfo['audit_method'] = $groupData[0]['audit_method'];
                $groupInfo['audit_scope'] = $groupData[0]['audit_scope'];
                $groupInfo['auditee'] = $groupData[0]['auditee'];
                $groupInfo['methods_id'] = $groupData[0]['methods_id'];

                $response = array('status' => 1, 'data' => $groupInfo);
            } else {
                $response = array('status' => '0', 'message' => "No any group available on this audit.");
            }
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    public function auditWorkSheetPDF() {
        //Configure::write('debug',0);

        $this->loadModel('User');
        $this->loadModel('Audit');

        ini_set('memory_limit', '4096M');
        ini_set('max_execution_time','500000');

        $response = array();

        if ($this->request->isPost() && !empty($this->request->data)) {

            $audits_id = $this->request->data['audits_id'];
            $clients_id = $this->request->data['clients_id'];
            $email = $this->request->data['email']; 

            //"mate@i-comply.co";
            /*

            $auditData = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audits_id, 'Audit.clients_id' => $clients_id), 'fields' => array('Audit.*')));

            $user_id= $auditData['Audit']['users_id'];
            $username= $auditData['Audit']['auditer_name'];

            $userData = $this->User->find('first', array('conditions' => array('User.id' => $user_id, 'User.username' => $username), 'fields' => array('User.*')));

            $email= $userData['User']['email'];
            
            */

            // $email = "mate@i-comply.co" ; //$this->request->data['email_id'];

            $groupData = $this->Audits->getAuditWorkSheetDetail($audits_id, $clients_id);
            $pdfname = "auditWorkSheetDetails" . '.pdf';
            App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));

            /*$mpdf = new mPDF('c', 'A4', '12');
            $mpdf->writeHTML($groupData); // All result from database write here

            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');

            $msg = Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname;
            if ($msg) {
                $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => $msg);
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
            }*/
            ob_start();
            error_reporting(0);
            $mpdf = new mPDF('c', 'A4', '12');
            $mpdf->writeHTML($groupData); // All result from database write here
            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');
            $senderEmail = DEFAULT_EMAIL_ADDRESS;
            $message = "Please click on below link <br>";
            $message.= "<a href=" . Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname . ">Download</a>";
            $subject = "audit worksheet";
            $msg = Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname;
            if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message)) {
                $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => $msg);
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
            }

        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }





    public function getAuditWorkSheetPDF() {
        //Configure::write('debug',0);
        Configure::write('debug',0);
        $this->loadModel('User');
        $this->loadModel('Audit');
        //ini_set('memory_limit', '4096M');
        // ini_set('max_execution_time','500000');
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $audits_id = $this->request->data['audits_id'];
            $clients_id = $this->request->data['clients_id'];
            $email = $this->request->data['email']; 
            //"mate@i-comply.co";
            /*$auditData = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audits_id, 'Audit.clients_id' => $clients_id), 'fields' => array('Audit.*')));
            $user_id= $auditData['Audit']['users_id'];
            $username= $auditData['Audit']['auditer_name'];
            $userData = $this->User->find('first', array('conditions' => array('User.id' => $user_id, 'User.username' => $username), 'fields' => array('User.*')));
            $email= $userData['User']['email'];
            */
           // $email = "mate@i-comply.co" ; //$this->request->data['email_id'];
            $groupData = $this->Audits->getAuditWorkSheetDetail($audits_id, $clients_id);
            $pdfname = "auditWorkSheetDetails" . '.pdf';
            App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
            /*$mpdf = new mPDF('c', 'A4', '12');
            $mpdf->writeHTML($groupData); // All result from database write here

            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');

            $msg = Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname;
            if ($msg) {
                $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => $msg);
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
            }*/
            ob_start();
            $mpdf = new mPDF('c', 'A4', '12');
            $mpdf->writeHTML($groupData, 0); // All result from database write here
            //$mpdf->AddPage('','','','','','','','','','','','html_MyHeader2', '', 'html_MyFooter2', '', 0, 0, 0, 0);
            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');
            $senderEmail = DEFAULT_EMAIL_ADDRESS;
            $message = "Please Find the attachment";
            $subject = "Audit WorkSheet";
            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
            $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;
            $attachment = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname;
            if(empty($email)){
                if ($msg) {
                        $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => (string)$msg);
                } else {
                        $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
                    }
            }else{

                if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachment)) {
                        $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
                    } else {
                        $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
                    }
                }
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }



        public function printCertificate() {
            
            Configure::write('debug', 0);
        //echo Router::fullbaseUrl(); exit;
            $this->loadModel('User');
            $this->loadModel('Audit');
            $this->loadModel('AuditPercentage');

            $response = array();
            $Array = array();
            if ($this->request->isPost() && !empty($this->request->data)) {

            $audits_id = $this->request->data['audits_id'];
            $clients_id = $this->request->data['clients_id'];
            $email = $this->request->data['email']; //"mate@i-comply.co";
            
            $auditData = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.id' => $audits_id)));
            $auditCount = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.is_deleted' => '0')));
            $noOfAuditTillDate= count($auditCount);

            $AuditDate= date_format(date_create($auditData[0]['Audit']['audit_date']),"dmY"); 
            $AuditDateN= date_format(date_create($auditData[0]['Audit']['audit_date']),"d F Y");

            /*Avg Score for respective year start*/
            $auditPercentage = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.audits_id' => $audits_id, "AuditPercentage.percentage NOT IN ('','-','-1')"))); 
            //,'AuditPercentage.percentage !=' => 0, 
            // 
            foreach($auditPercentage as $avg){
                $Array[]= $avg['AuditPercentage']['percentage'];  
            }
            
            $$AuditScore1 = 0;
            if(isset($avgArray) && !empty($avgArray)){
                $AuditScore1 = array_sum($Array) / count($Array); 
            }
            $AuditScore = round($AuditScore1, 2);
            /*Avg Score for respective year end*/

            
            /*Avg Score for overall years start*/
            $auditPercentage = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.clients_id' => $clients_id, "AuditPercentage.percentage NOT IN ('','-','-1')"))); 
            //,'AuditPercentage.percentage !=' => 0, 
            // 'AuditPercentage.audits_id' => $audits_id,
            foreach($auditPercentage as $avg){
                $avgArray[]= $avg['AuditPercentage']['percentage'];  
            }
            
            $$AuditScore1 = 0;
            if(isset($avgArray) && !empty($avgArray)){
                $AuditScore1 = array_sum($avgArray) / count($avgArray); 
            }
            $avgAuditScore = round($AuditScore1, 2);
            /*Avg Score for overall years end*/


            if(!empty($auditData[0]['Audit']['date_of_certificate_issue'])){
                $date= $auditData[0]['Audit']['date_of_certificate_issue'];
            }else{

                $date=  date("d-m-Y");

                $savedate = array(
                    'Audit.date_of_certificate_issue' => "'".$date."'"
                    );
                $condition = array(
                    'Audit.id' => $audits_id,
                    'Audit.clients_id' => $clients_id
                    );
                $errr= $this->Audit->updateAll($savedate, $condition);
            }

            if(strlen($auditData[0]['Client']['company_name']) > 16 ){
                $titleFontSize = "40px";
            }else{
                $titleFontSize = "40px"; 
            }
            $site_url = Router::fullbaseUrl();
            $content = '
            <style>
                @font-face {
                    font-family: "dynalight";
                    src: url("fonts/Dynalight-Regular.otf") format("truetype");
                }
                .wrap {
                    width: 100%;
                    background-image: url(images/bgimg.jpg);
                    background-repeat: no-repeat;
                    background-image-resize:0;
                    background-size:100% 100%;
                    background-position: center center;
                    margin: 0px auto;
                    background-color: #eef0f8;
                    background-image-resize:6;
                    padding-bottom:25px;
                }
                .padd30 {
                    padding: 30px;
                }
                .logo {
                    float: right;
                    width: 188px;
                    height: 54px;
                }
                .address{ 
                    float: right;
                    font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal; 
                    font-size: 14px;
                }
                .certificateimg {
                    float: right;
                    width: 429px;
                    height: 61px;
                    margin-top: 28px;
                    margin-bottom: 60px;
                }
                .content {
                    float: right;
                }
                .fnt {
                    font-size: '.$titleFontSize.';
                    font-family: dynalight;
                    font-weight: 300;
                    color: #254d7e;
                    border-bottom: 1px solid #ccc;
                    text-align: center; font-family: 
                }
                .fntbtm {
                    font-size: 26px;
                    font-family: dynalight;
                    font-weight: 300;
                    color: #254d7e;
                    border-bottom: 1px solid #ccc;
                    text-align: center;
                }

                .divtable {
                    float: right;
                    margin-top: 30px;
                    width: 450px;
                    font-family: Gotham, "Helvetica Neue", Helvetica, Arial, "sans-serif";
                }
                .date {
                    float: right;
                    width: 50%;
                    padding-top: 90px;
                    text-align: center; 
                }
                .sign {
                    float: right;
                    width: 50%;
                    padding-top: 90px;
                    text-align: center;
                }
                .clear {
                    clear: both;
                }
                .floatR{
                    float: right;
                    margin-left: 50%;
                }
            </style>

            <div class="wrap" >
              <div class="padd30">
                <div class="logo"><img src="'.$site_url.'/images/logo.png" alt=""/></div>
                <div class="clear"></div>
                <div class="certificateimg"> <img src="'.$site_url.'/images/cerificate_img.png" alt=""/></div>
                <div class="clear"></div>
                <div class="content">
                  <div style="font-size:25px; text-align: right;"><i>This is to certify that </i> <span class="fnt">'.$auditData[0]['Client']['company_name'].'</span> <br>
                    <i>achieved</i><span class="fnt">  '.$AuditScore.'%</span> <i>Compliance.</i></div>
                </div>
                <div class="clear"></div>
                <div class="divtable">
                  <table width="450" border="0" cellspacing="0" cellpadding="0" style="text-align: right;" >
                    <tbody>
                      <tr>
                        <td width="175 vertical-align: top;
                        padding: 5px;"><strong>Date of audit:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$AuditDateN.'</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Audit Scope:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$auditData[0]['Audit']['audit_scope'].'</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Location of audit:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$auditData[0]['Audit']['audit_name'].'</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Standards audited:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$auditData[0]['Audit']['audit_standards'].'</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top; 
                        padding: 5px;"><strong>Number of audits to date:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$noOfAuditTillDate.'</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Average audit score for all
                        audits at this location:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">'.$avgAuditScore.'%</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Certificate No:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">ICA'.$AuditDate.'00'.$auditData[0]['Audit']['amount_of_days_audit'].'</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="clear"></div>
        <div class="sign" >
          <div class="floatR"><img src="'.$site_url.'/images/signature.png" alt=""/><br>
            <i style="font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal;">Signature</i></div>
        </div>
        <div class="date">
          <div class="floatR"><span class="fntbtm"> '.$date.'</span><br>
            <i style="font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal;">Date</i></div>
        </div>
        <div class="clear"></div>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p> 
    </div>
</div>
';  
//echo $content; die; 
$pdfname = "compliance_certificate" . '.pdf';
App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));

ob_start();
error_reporting(0);
$mpdf = new mPDF('', 'A4', '12', '', '2', '2', '2', '2');
//$mpdf->showImageErrors = true;

            $mpdf->writeHTML($content); // All result from database write here
            $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');
           //$senderEmail = DEFAULT_EMAIL_ADDRESS;
           // $message = "Please click on below link <br>";
           // $message.= "<a href=" . Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname . ">Download</a>";
           // $subject = "compliance certificate";
            $msg = SITE_LINK . "/app/webroot/files/pdf/" . $pdfname;

            if ($msg) {
                $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => $msg);
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
            }


            
        }

        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();

    }

    public function getCertificate() {
        Configure::write('debug', 0); 
        $this->loadModel('User');
        $this->loadModel('Audit');
        $this->loadModel('AuditPercentage');
        $response = array();
        if ($this->request->isPost() && !empty($this->request->data)) {
            $audits_id = $this->request->data['audits_id'];
            $clients_id = $this->request->data['clients_id'];
            $email = $this->request->data['email']; //"mate@i-comply.co";            
            $haveSubOffice = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.process_id')));
            $processId = $haveSubOffice['Audit']['process_id'];
            if ($processId != 0) {
                $subofficeInfo = $this->UtilityFunction->getOfficeInfoByProcessId($processId);
            }
            if ($processId != 0) {
                $auditData = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.id' => $audits_id)));
                if (is_array($auditData) && count($auditData) > 0) {
                    $auditName = $auditData[0]['Audit']['audit_name'];
                }
                if ($processId != 0) {
                    $auditCount = $this->Audit->find('all', array(
                                'conditions' => array(
                                    'Audit.clients_id' => $clients_id,
                                    // 'cso.id'            =>  $processId,
                                    'Audit.is_deleted' => '0',
                                    'Audit.audit_name LIKE' => $auditName,
                                )
                            )
                    );         
                } else {
                    $auditCount = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.is_deleted' => '0')));                  
                }
                $noOfAuditTillDate = count($auditCount);
                $AuditDate = date_format(date_create($auditData[0]['Audit']['audit_date']), "dmY");
                $AuditDateN = date_format(date_create($auditData[0]['Audit']['audit_date']), "d F Y");
                /* Avg Score for respective year start */
                $clientDataPerArr = $this->AuditPercentage->find('all', array(
                            'fields' => ['percentage'],
                            'conditions' => [
                                'AuditPercentage.audits_id' => $audits_id,
                                "AuditPercentage.percentage NOT IN ('','-','-1')",
                            ],
                            'order' => array('YEAR(AuditPercentage.created_date)' => 'asc'),
                        )
                );
                $perCnt = 0;
                $AuditScore = 0;
                $tCpercentage = 0;
                if (isset($clientDataPerArr) && is_array($clientDataPerArr) && count($clientDataPerArr) > 0) {
                    foreach ($clientDataPerArr as $clientPer) {
                        $perCnt++;
                        $tCpercentage += $clientPer['AuditPercentage']['percentage'];
                    }
                    $AuditScore = round($tCpercentage / $perCnt, 2);
                }               

                /* Avg Score for respective year end */
                /* Avg Score for overall years start */
                $auditDataArr = $this->Audit->find('all', array(
                    'fields' => ['Audit.id'],
                    'conditions' => array(
                        'Audit.clients_id' => $clients_id,
                        // 'cso.id'            =>  $processId,
                        'Audit.is_deleted' => '0',
                        'Audit.audit_name LIKE' => $auditName,
                    )
                        )
                );
                if (is_array($auditDataArr) && count($auditDataArr) > 0) {
                    foreach ($auditDataArr as $auditKey => $auditVal) {
                        $apConditions = [
                            'AuditPercentage.audits_id' => $auditVal['Audit']['id'],
                            "AuditPercentage.percentage NOT IN ('','-','-1')",
                        ];
                        $avgClientDataPerArr = $this->AuditPercentage->find('all', array(
                            'fields' => ['percentage'],
                            'conditions' => $apConditions,
                            'order' => array('YEAR(AuditPercentage.created_date)' => 'asc'),
                                )
                        );
                        $allLocationData[$auditKey] = $avgClientDataPerArr;
                    }
                }
                $totalPerData = 0;
                $totalCnt = 0;
                if (isset($allLocationData) && is_array($allLocationData) && count($allLocationData) > 0) {
                    foreach ($allLocationData as $clientPer) {
                        $totalCnt++;
                        $tpercentage = 0;
                        $perCount = 0;
                        foreach ($clientPer as $client) {
                            $perCount++;
                            $tpercentage += $client['AuditPercentage']['percentage'];
                        }
                        $totalPerData += $tpercentage / $perCount;
                    }
                }
                $AuditScore1 = $totalPerData / $totalCnt;

                $avgAuditScore = round($AuditScore1, 2);
                /* Avg Score for overall years end */
                if (!empty($auditData[0]['Audit']['date_of_certificate_issue'])) {
                    $date = $auditData[0]['Audit']['date_of_certificate_issue'];
                } else {
                    $date = date("d-m-Y");
                    $savedate = array(
                        'Audit.date_of_certificate_issue' => "'" . $date . "'"
                    );
                    $condition = array(
                        'Audit.id' => $audits_id,
                        'Audit.clients_id' => $clients_id
                    );
                    $errr = $this->Audit->updateAll($savedate, $condition);
                }


                if (strlen($auditData[0]['Client']['company_name']) > 16) {
                    $titleFontSize = "40px";
                } else {
                    $titleFontSize = "40px";
                }

                if ($processId != 0) {
                    $companyname = $subofficeInfo['label'];
                    $companyName = $subofficeInfo['label'];
                    $auditscope = $auditData[0]['Audit']['audit_scope'];
                    $locationOfAudit = $auditData[0]['Audit']['audit_name'];
                } else {
                    $companyname = $auditData[0]['Client']['company_name'];
                    $auditscope = $auditData[0]['Audit']['audit_scope'];
                    $locationOfAudit = $auditData[0]['Audit']['audit_name'];
                }
                $content = '
            <style>
                @font-face {
                    font-family: "dynalight";
                    src: url("fonts/Dynalight-Regular.otf") format("truetype");
                }
                .wrap {
                    width: 100%;
                    background-image: url(images/bgimg.jpg);
                    background-repeat: no-repeat;
                    background-image-resize:0;
                    background-size:100% 100%;
                    background-position: center center;
                    margin: 0px auto;
                    background-color: #eef0f8;
                    background-image-resize:6;
                    padding-bottom:20px;
                }
                .padd30 {
                    padding: 30px;
                }
                .logo {
                    float: right;
                    width: 188px;
                    height: 54px;
                }
                .address{ 
                    float: right;
                    font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal; 
                    font-size: 14px;
                }
                .certificateimg {
                    float: right;
                    width: 429px;
                    height: 61px;
                    margin-top: 28px;
                    margin-bottom: 50px;
                }
                .content {
                    float: right;
                }
                .fnt {
                    font-size: ' . $titleFontSize . ';
                    font-family: dynalight;
                    font-weight: 300;
                    color: #254d7e;
                    border-bottom: 1px solid #ccc;
                    text-align: center; font-family: 
                }
                .fntbtm {
                    font-size: 26px;
                    font-family: dynalight;
                    font-weight: 300;
                    color: #254d7e;
                    border-bottom: 1px solid #ccc;
                    text-align: center;
                }

                .divtable {
                    float: right;
                    margin-top: 30px;
                    width: 450px;
                    font-family: Gotham, "Helvetica Neue", Helvetica, Arial, "sans-serif";
                }
                .date {
                    float: right;
                    width: 50%;
                    padding-top: 90px;
                    text-align: center; 
                }
                .sign {
                    float: right;
                    width: 50%;
                    padding-top: 90px;
                    text-align: center;
                }
                .clear {
                    clear: both;
                }
                .floatR{
                    float: right;
                    margin-left: 50%;
                }
            </style>

            <div class="wrap" >
              <div class="padd30">
                <div class="logo"><img src="images/logo.png" alt=""/></div>
                <div class="clear"></div>
                <div class="certificateimg"> <img src="images/cerificate_img.png" alt=""/></div>
                <div class="clear"></div>
                <div class="content">
                  <div style="font-size:25px; text-align: right;"><i>This is to certify that </i> <span class="fnt">' . $companyname . '</span> <br>
                    <i>achieved</i><span class="fnt">  ' . $AuditScore . '%</span> <i>Compliance.</i></div>
                </div>
                <div class="clear"></div>
                <div class="divtable">
                  <table width="450" border="0" cellspacing="0" cellpadding="0" style="text-align: right;" >
                    <tbody>
                      <tr>
                        <td width="175 vertical-align: top;
                        padding: 5px;"><strong>Date of audit:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $AuditDateN . '</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Audit Scope:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $auditscope . '</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Location of audit:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $locationOfAudit . '</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Standards audited:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $auditData[0]['Audit']['audit_standards'] . '</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top; 
                        padding: 5px;"><strong>Number of audits to date:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $noOfAuditTillDate . '</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Average audit score for all
                        audits at this location:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">' . $AuditScore . '%</td>
                    </tr>
                    <tr>
                        <td style="vertical-align: top;
                        padding: 5px;"><strong>Certificate No:</strong></td>
                        <td width="225" style="text-align: left; vertical-align: top;
                        padding: 5px;">ICA' . $AuditDate . '00' . $auditData[0]['Audit']['amount_of_days_audit'] . '</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="clear"></div>
        <div class="sign" >
          <div class="floatR"><img src="images/signature.png" alt=""/><br>
            <i style="font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal;">Signature</i></div>
        </div>
        <div class="date">
          <div class="floatR"><span class="fntbtm"> ' . $date . '</span><br>
            <i style="font-family: Gotham, Helvetica Neue, Helvetica, Arial, sans-serif; font-style: normal;">Date</i></div>
        </div>
        <div class="clear"></div>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>                    
    </div>
</div>
';

                $pdfname = "compliance_certificate" . '.pdf';
                App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));

                ob_start();
                error_reporting(0);
                $mpdf = new mPDF('', 'A4', '12', '', '2', '2', '2', '2');
                $mpdf->writeHTML($content); // All result from database write here
                $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname, 'F');
                $senderEmail = DEFAULT_EMAIL_ADDRESS;
                $attachment = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/files/pdf/" . $pdfname;
                $message = "Please find the attachment.";
                $subject = "compliance certificate";
                $msg = Router::fullbaseUrl() . "/app/webroot/files/pdf/" . $pdfname;
                if (empty($email)) {
                    if ($msg) {
                        $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => (string) $msg);
                    } else {
                        $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
                    }
                } else {

                    if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachment)) {
                        $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
                    } else {
                        $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!', 'data' => 'Email not sent. Please try again!');
                    }
                }
            }

            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }

    public function addSummary() {
        Configure::write('debug',0);
        $this->loadModel('User');
        $this->loadModel('Audit');
        
        $response = array();

        if ($this->request->isPost() && !empty($this->request->data)) {

            $audits_id = $this->request->data['audits_id'];
            $clients_id = $this->request->data['clients_id'];
            $summary = $this->request->data['summary'];

            $savedata = array(
                'Audit.audit_summary' => "'".$summary."'"
                );

            $condition = array(
                'Audit.id' => $audits_id,
                'Audit.clients_id' => $clients_id
                );
            
            if ($this->Audit->updateAll($savedata, $condition)) {
                $response = array('status' => BOOL_TRUE, 'message' => 'Audit summary saved successfully', 'data' => 'Audit summary saved successfully');
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'Summary not saved. Please try again!');
            }

        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }

    
    
    
    
     public function getSummary() {      
//        Configure::write('debug',2);     
        $this->loadModel('Audit');        
        $response = array();    
        if ($this->request->isPost() && !empty($this->request->data)) {
           
            $audits_id = $this->request->data['audits_id']; 
            $clients_id = $this->request->data['clients_id'];
            $response = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audits_id,'Audit.clients_id' => $clients_id), 'fields' => array('Audit.audit_summary','Audit.id')));
        }
        if($response){
             $response = array('status' => BOOL_TRUE, 'data' => $response);
        }else{
             $response = array('status' => 0,  'data' => 'Not Found responses');
        }
       
       
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    
    
    
    
    
    
    
    

    public function getDefaultResponses() {
        Configure::write('debug',0);
        //$this->loadModel('Group');
        $this->loadModel('DefaultResponse');

        $response = array();
        //$groups_id = $this->request->data['groups_id'];
        //if(!empty($groups_id)){
            //if ($this->request->isPost() && !empty($this->request->data)) {
                $getResp = $this->DefaultResponse->find('all', array('conditions' => array('DefaultResponse.is_deleted' => 0))); //'DefaultResponse.group_id' => $groups_id, 
                if ($getResp) {
                    $response = array('status' => BOOL_TRUE, 'message' => 'Found responses.', 'data' => $getResp);
                } else {
                    $response = array('status' => BOOL_FALSE, 'message' => 'Response not found for this group.');
                }
            //}
        /*}else{
            $response = array('status' => BOOL_FALSE, 'message' => 'Please enter the group id.');
        }*/
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }


    public function getDefaultResponsesAutofill() {
        Configure::write('debug',0);
        $this->loadModel('DefaultResponse');

        $response = array();
        $comment = '%'.$this->request->data['comment'].'%'; //'%'.
        if(!empty($comment)){
            if ($this->request->isPost() && !empty($this->request->data)) {
                $getResp = $this->DefaultResponse->find('all', array('conditions' => array('DefaultResponse.is_deleted' => 0, 'DefaultResponse.response LIKE ' => $comment)));
                if ($getResp) {
                    $response = array('status' => BOOL_TRUE, 'message' => 'Found responses.', 'data' => $getResp);
                } else {
                    $response = array('status' => BOOL_FALSE, 'message' => 'Response not found for this group.');
                }
            }
        }else{
            $response = array('status' => BOOL_FALSE, 'message' => 'Please start typing the comment.');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }


    public function saveClientAuditQuestion($clientId,$groupId,$auditId,$userId) {
     Configure::write('debug',2);
     $response = $this->UtilityFunction->saveClientAuditQuestion($clientId,$groupId,$auditId,$userId);
     $this->saveLogBeforeRetruning($response);
     return  $response;      
 }     


 public function getAuditReport() {
    Configure::write('debug',0);
   $response = array();
   if ($this->request->isPost() && !empty($this->request->data)) {
    $audits_id = $this->request->data['audits_id'];
    $clients_id = $this->request->data['clients_id'];
    $email = $this->request->data['email'];
    App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
    $this->loadModel('Audit');
    $this->loadModel('AuditGroupQuestion');
    $this->loadModel('Client');
    $this->loadModel('Question');
    $this->loadModel('AuditGroupQuestionComments');
    $this->loadModel('AuditGroupComment');
    $haveSubOffice = $this->Audit->find('first', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.process_id')));
    $processId = $haveSubOffice['Audit']['process_id'];
    if($processId != 0){
        $subofficeInfo = $this->UtilityFunction->getOfficeInfoByProcessId($processId);
    }
    $AuditDates = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.is_deleted' => 0), 'fields' => array('Audit.audit_date')));
    $scoreArr = array();
    $getArr = array();
    if ($clients_id != null && $audits_id != null) {
        $getArr = $this->AuditGroupQuestion->getAuditsQuestionsArr($clients_id, $audits_id);
    }   

    if (!empty($getArr)) {
        $pdfname = "auditReportPdf" . time() . '.pdf';
        $i = 0;
        $contact_person_name = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.contact_person_name')));
        foreach ($getArr as $auditID) {
            $auditData['Audit'] = $auditID['Audit'];
            $companyName = $auditID['Client']['company_name'];
            $clients_id = $auditID['Audit']['clients_id'];
            if (!empty($clients_id)) {
                $getClientDetail = $this->Client->find('first', array('conditions' => array('Client.id' => $clients_id)));
                if (!empty($getClientDetail)) {
                    $clientDetail['client_email'] = $getClientDetail['Client']['email'];
                    $clientDetail['client_contact'] = $getClientDetail['Client']['contact_name'];
                    $clientDetail['client_contact_name'] = $getClientDetail['Client']['client_name'];
                    $clientDetail['phone_number'] = $getClientDetail['Client']['phone_number'];
                    $auditData['clientDtail'] = $clientDetail;
                } else {
                    $auditData['clientDtail'] = array();
                }
            }
            $dataArr[0][0]['avgPercentage'] = '100';
            if (!empty($auditID['AuditGroup'])) {
                foreach ($auditID['AuditGroup'] as $val) {
                    $groupArrID[] = $val['groups_id'];
                    $getCompyNScore = $this->AuditGroupQuestionComments->getAllComplyScore($val['groups_id'], $audits_id, $clients_id);
                    $AuditGroupCommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.groups_id' => $val['groups_id'], 'AuditGroupComment.audits_id' => $audits_id, 'AuditGroupComment.clients_id' => $clients_id, 'AuditGroupComment.is_deleted' => 0, 'AuditGroupComment.action' => array('NC','OB')), 'fields' => array('AuditGroupComment.comment,AuditGroupComment.action,AuditGroupComment.image,AuditGroupComment.groups_id')));
                    $question = "";
                    if (!empty($getCompyNScore)) {
                        foreach ($getCompyNScore as $getCompyNScoreArr) {
                                    //print_r($groupEndTime);
                            $queGrpID = !empty($getCompyNScoreArr['AuditGroupQuestionComments']['questions_id']) ? $getCompyNScoreArr['AuditGroupQuestionComments']['questions_id'] : 0;
                            $getQuestion = $this->Question->find('first', array('conditions' => array('Question.id' => $queGrpID)));

                            $question = !empty($getQuestion['Question']['question']) ? $getQuestion['Question']['question'] : "";
                                    $dataArr['auditsId']= $getCompyNScoreArr['AuditGroupQuestionComments']['audits_id']; // by swati t
                                    $dataArr['groupqueID']= $getCompyNScoreArr['AuditGroupQuestionComments']['id']; // by swati t
                                    $dataArr['audit_question'] = $getQuestion['Question']['question'];
                                    //$dataArr['percentage'] = $getCompyNScoreArr['AuditGroupQuestionComments']['percentage'];
                                    $dataArr['comment'] = $getCompyNScoreArr['AuditGroupQuestionComments']['comment'];
                                    $dataArr['created_date'] = $getCompyNScoreArr['AuditGroupQuestionComments']['created_date']; // by swati t
                                    $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image']; // by swati t

                                    $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image'];
                                    $dataArr['action_code'] = $getCompyNScoreArr['AuditGroupQuestionComments']['action'];
                                    $dataArr['groupName'] = $val['group_name'];
                                    $scoreArr[] = $dataArr;
                                }

                                $this->loadModel('AuditPercentage');
//                                $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.audits_id' => $audits_id, 'AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage !=' => ''), 'fields' => array('AuditPercentage.end_time', 'AuditPercentage.percentage', 'AuditPercentage.groups_id'), 'order' => array('AuditPercentage.groups_id ASC')));
//                                $dataArr = $this->AuditPercentage->find('all', array('fields' => array('AVG(percentage) as avgPercentage'), 'conditions' => array('AuditPercentage.clients_id' => $clients_id, 
//                                    'AuditPercentage.audits_id' => $audits_id,
//                                    "AuditPercentage.percentage NOT IN ('','-','-1',' ')"), 'group' => 'audits_id'));
                                ///*'AuditPercentage.percentage !=' => 0, */ //By Swati T @14Dec2018
                                $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.groups_id >' => '0','AuditPercentage.audits_id' => $audits_id, 'AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage !=' => ''), 'fields' => array('AuditPercentage.end_time', 'AuditPercentage.percentage', 'AuditPercentage.groups_id'), 'order' => array('AuditPercentage.groups_id ASC')));
                                $dataArr = $this->AuditPercentage->find("all", array(
                                "fields"     => array("AVG(AuditPercentage.percentage) AS avgPercentage"),
                                "conditions" => array('AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage >= ' => '0',
                                    'AuditPercentage.audits_id' => $audits_id)
                                ));
                                
                                
                                
                                
                                
                                
                                $auditData['complyScore1'] = array();

                                foreach ($AuditPercentageArr as $AuditPercentageNewArr) {
                                    $groupInfo = $this->Audits->getAllGroupsByGroupId($AuditPercentageNewArr['AuditPercentage']['groups_id']);

                                    $dataArr1['percentage'] = $AuditPercentageNewArr['AuditPercentage']['percentage'];
                                    $dataArr1['end_time'] = $AuditPercentageNewArr['AuditPercentage']['end_time'];
                                    $dataArr1['groupName1'] = $groupInfo[0]['full_name'];
                                    $auditData['complyScore1'][] = $dataArr1;
                                }
                            }
                            if (!empty($AuditGroupCommentArr)) {
                                //print_r($AuditGroupCommentArr); exit;
                                //$scoreArrAudit = array();
                                foreach ($AuditGroupCommentArr as $AuditGroupCommentNewArr) {
                                    // $groupID= $AuditGroupCommentNewArr['AuditGroupComment']['groups_id'];
                                    //$groupName[0]['AuditGroup']['group_name'] = $this->AuditGroup->find('all',array('conditions'=>array('AuditGroup.groups_id'=>$groupID),'fields' => array('AuditGroup.group_name')));
                                    $dataArr['comment'] = $AuditGroupCommentNewArr['AuditGroupComment']['comment'];
                                    $dataArr['image'] = $AuditGroupCommentNewArr['AuditGroupComment']['image'];
                                    $dataArr['action_code'] = $AuditGroupCommentNewArr['AuditGroupComment']['action'];
                                    $dataArr['audit_question'] = "";
                                    $dataArr['groupName'] = $val['group_name'];
                                    $scoreArr[] = $dataArr;
                                }
                            }

                            $i++;
                        }
                        $auditData['complyScore'] = $scoreArr;
                    } else {
                        $auditData['complyScore'] = $scoreArr;
                    }

                    $i++;
                    $scheduleDateArr = array();
                    if (!empty($auditID['AuditGroupSchedule'])) {
                        foreach ($auditID['AuditGroupSchedule'] as $val1) {
                            $schedulArr[] = $val1['schedule_date'];
                        }
                        $auditData['scheduledates'] = $schedulArr;
                    } else {
                        $auditData['scheduledates'] = array();
                    }
                }
       
               if($processId != 0){
                   $contact_person_name[0]["Audit"]["contact_person_name"] = $subofficeInfo['contact_name'];
                   $auditData["Audit"]["client_name"] = $subofficeInfo['label'];
                   $auditData["clientDtail"]["phone_number"] = $subofficeInfo['organization_phone'];
                   $auditData["clientDtail"]["client_email"] = $subofficeInfo['email'];
                   $companyName = $subofficeInfo['label'];
               } 
  
                $content = '<style>               
                body, table, td, p, a, li, blockquote {
                    -webkit-text-size-adjust: none !important;
                    font-family: Arial;
                    color: #666;
                    font-size: 14px;
                }
                element.style {
                    font-size: 14px;
                }
                *::after, *::before {
                box-sizing: border-box;
            }
                *::after, *::before {
            box-sizing: border-box;
        }
        b, strong {
            font-weight: 700;
        }
                * {
        box-sizing: border-box;
    }
    label {
        cursor: default;
    }
    body {
        font-family: "Open Sans",sans-serif;
        line-height: 1.42857;
        font-size: 14px;
        line-height: 1.42857;
    }
                *::after, *::before {
    box-sizing: border-box;
}
                *::after, *::before {
box-sizing: border-box;
}
.mar-0-auto{
    margin: 0 auto;
}
.tbl-border-white{
    border: 1px solid #fff
}
.tbl-border-white td, .tbl-border-white th{
    border: 1px solid #fff;
    padding: 10px;
}
.tbl-border-black{
    border: 1px solid #fff;
}
.tbl-border-black td, .tbl-border-black th{
    border: 1px solid #333;
    padding: 10px;
}
.tbl-border-blackk td, .tbl-border-blackk th{
    border: 1px solid #fff;
    border-bottom-width:3px;
    padding: 10px;
}
@page :first{
    background: #00b3ec;
}
@page :last{
    background: #00b3ec;
}
@page {
  size: auto;
  odd-header-name: html_MyHeader1;
  odd-footer-name: html_MyFooter1;
}
</style>
<body>
    <table border="0" cellpadding="0" cellspacing="0" width="100%" class="mar-0-auto">
        <tr>
            <td>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td>
                            <img src="images/logo_new.png" alt="">
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 32px; color: #000; font-weight: 600">
                            Audit Report for
                        </td>
                    </tr>
                </table>
                <table border="0" cellpadding="0" cellspacing="0" width="" >
                    <tr>
                        <td style="font-size: 70px; color: #fff; font-weight: 600; text-transform: uppercase">
                            '.$companyName.'
                        </td>
                    </tr>
                </table><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
                <table cellpadding="0" cellspacing="0" width="100%" class="tbl-border-white" style="margin: 30px 0px; ">
                    <tr>
                        <td rowspan="4" style="font-size: 18px; color: #fff;">
                            <strong> Prepared for:</strong><br/>
                            ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '<br/>
                            ' . $auditData["Audit"]["client_name"] . '<br/>
                            ' . $auditData["clientDtail"]["phone_number"] . '<br>
                            ' . $auditData["clientDtail"]["client_email"] . '
                        </td>';
                        /*Code modification done by swati T 04-12-2018 start*/
                        $msg2 = '';                                        
                        $msg2 .= '<td style="font-size: 18px; color: #fff;">';
                        $msg2 .= '<strong> Dates: </strong><br/>'; 
                                        /*foreach ($AuditDates as $auditdate) {
                                            $dates= $auditdate['Audit']['audit_date'];
                                            $date= date_format(date_create($dates), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';   
                                        }*/ /*by Swati T */

                                        if(count($auditData['scheduledates']) > 0 ){
                                        foreach ($auditData['scheduledates'] as $value) {
                                            /*$msg2 .= '<td style="font-size: 18px; color: #fff;">';
                                            $msg2 .= '<strong> Date: </strong>'. $value . 
                                            '</td>';*/
                                            $date= date_format(date_create($value), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';
                                        } // Updated by Swati T
                                        }else{
                                            $auDate = $auditData["Audit"]["audit_date"];
                                            $date= date_format(date_create($auDate), 'jS F Y, l');
                                            $msg2 .=  $date . '<br/>';
                                        }
                                        /*Code modification done by swati T 04-12-2018 end*/
                                        $content .= $msg2 . '</td></tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> Location of Audit: </strong> ' . $auditData["Audit"]["audit_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> iComply Auditor Name: </strong> ' . $auditData["Audit"]["auditer_name"] . '
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="font-size: 18px; color: #fff;">
                                                <strong> No. of Audit Days: </strong>' . $auditData["Audit"]["amount_of_days_audit"] . '
                                            </td>
                                        </tr>
                                    </table></td></tr></table>';

                            /*$content .= '<div style="page-break-after: always;"></div>';
                            $content .=  '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table border="0" cellpadding="0" cellspacing="0" width="" >
                                <tr>
                                    <td style="font-size: 20px; color: #000;">
                                        ' . $contact_person_name[0]["Audit"]["contact_person_name"] . '
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-size: 20px; color: #00b3ec;">
                                       ' . $auditData["Audit"]["client_name"] . '
                                    </td>
                                </tr>
                            </table>';*/
                            $content .= '<div style="page-break-after: always;"></div>';
                            $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:45px; color: #000; font-weight: bold">
                                    Thank you for letting us audit your organization!!
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Audit Summary
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                   ' .str_replace("\n", "<br />", $auditData["Audit"]["audit_summary"]). '
                                </td>
                            </tr>
                        </table>
                        <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                            <tr>
                                <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                    Scope of audit
                                </td>
                            </tr>
                            <tr>
                                <td style="font-size:16px; color: #000;">
                                 ' . $auditData["Audit"]["audit_scope"] . '
                             </td>
                         </tr>
                     </table>
                     <table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                        <tr>
                            <td style="font-size:18px; color: #00b3ec; font-weight: 600; text-transform: uppercase; line-height: 40px">
                                Standard(s)
                            </td>
                        </tr>
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                ' . $auditData["Audit"]["audit_standards"] . '
                            </td>
                        </tr>
                    </table>
                    ';
                    $content .= '<div style="page-break-after: always;"></div>';            
                    $content .='<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                    <tr>
                        <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                            Compliance Scores<br><br><br>
                        </td>                                   
                    </tr> 
                    <tr >
                       <td style="font-size:16px; color: #000; line-height:22px;">
                        Would a game ever become popular if there was no scoring? We love scoring. It can help an organization or department become laser focused on improvement.<br><br> Our scoring method is objective because it is based on evidence presented during the audit. <br><br> For greater insights, the auditor will also provide the Audit worksheets from this audit. The Audit Worksheet will let you see, line by line, which areas of your organization are complying or lacking.
                    </td>
                </tr>                             
            </table>
            <table border="0" cellpadding="0" cellspacing="0" width="100%" class="tbl-border-blackk" style="margin: 30px 0px;">
                <tr>
                    <th style="font-size: 16px; color: #fff; background-color:#00b3ec;text-transform: uppercase;">
                        Group Name
                    </th>
                    <th style="font-size: 16px; color: #fff;background-color:#00b3ec;text-transform: uppercase;">
                        Compliance Score (%)
                    </th>
                </tr>';
                $msg = '';
                if (!empty($auditData['complyScore1'])) {
                    foreach ($auditData['complyScore1'] as $value) {
                      if($value["groupName1"] == ''){ continue; }
                        $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000;">';
                        if ($value["percentage"] == "0") {
                            $value["percentage"] = '0';
                        }
                        if ($value["percentage"] == "-1" || $value["percentage"] == "-") {
                            $value["percentage"] = '-';
                        }
                        if ($value["percentage"] == "") {
                            $value["percentage"] = '';
                        }
                        //                    $msg .= $value["groupName1"] . '</td><td>' . $value["percentage"] . '</td><td>' . $value["end_time"];

                        
                        $msg .= $value["groupName1"] ? $value["groupName1"] : "-" . '</td>';
                        $msg .= '<td style="font-size: 16px; color: #000;">'.$value["percentage"].'</td>';
                        $msg .= '</tr>';
                    }
                }

                
                $newCell = '';
                if(!empty($dataArr[0][0]['avgPercentage'])){
                    $msg .= '<tr style="background-color:#eeeeee;"><td style="font-size: 16px; color: #000; font-weight:bold; ">Average Compliance Score</td>';
                    if($dataArr[0][0]['avgPercentage'] == "-1" || $dataArr[0][0]['avgPercentage'] == "-" || $dataArr[0][0]['avgPercentage'] == ""){
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;"> - </td>';
                        //$msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? '-' : '-' . '</td></tr>';  
                    } else {
                        $newCell .= '<td style="font-size: 16px; color: #000; font-weight:bold;">'.round($dataArr[0][0]['avgPercentage'],2).'</td>';                            
                       // $msg .= 'Total Percentage' . '</th><td>' . (!empty($dataArr) ) ? round($dataArr[0][0]['avgPercentage'], 2) : '-' . '</td></tr>';
                    } 
                }
                //$newCell .= "<td>test<td>";

                $msg .= $newCell."</tr>";
               //swatihere
                $content .= $msg . '</table>';
                $content .= '<div style="page-break-after: always;"></div>'; 
                $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
                <tr>
                    <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                        Audit Report<br><br><br> 
                    </td>
                </tr>
                <tr style="margin: 30px 0px;">
                    <td>                       
                        <p style="font-size:16px; color: #000; margin: 30px 0px;">
                            The action code "NC" means non-conformance. A non-conformance either means you are not complying with your policies/procedures or the relevant standard.  If you receive an NC, your organization will need to correct the situation and start conforming. The action code "OB" means  Observation, or in other words a strong suggestion. You do not have to implement an observation, so we will leave that up to you to decide. Normally an observation is provided to help you improve.<br><br>
                        </p>
                        <p style="font-size:16px; color: #000;">
                            Here is your audit report…<br/><br/>
                        </p>
                    </td>
                </tr>
            </table>';
            $msg1 = '';
            $newMsg = '';
            $auditImage = '';
//                pr($auditData['complyScore']);
//                exit(__LINE__);
            $group_values = 1;

            foreach ($auditData['complyScore'] as $value) {                   
                $msg1 = '';
                if($value['action_code'] != ''){
                    if(!empty($value["image"])){
                        $auditImage = '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0;" >
                        <tr>
                            <td style="font-size:16px; color: #000;">
                                <img width="135" height="120" src="' . $value["image"].'" />
                            </td>
                        </tr>
                    </table>';  
                }else{
                    $auditImage='';
                }
                $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 8px 0px 0;">
                <tr>
                    <td style="text-align: center; font-weight: 600; font-size: 28px; color: #000">
                        Finding '.$group_values. '
                    </td>
                </tr>
            </table>';
                                        /*'.date('F j Y', strtotime($auditData["Audit"]["created_date"])).'*/ //Commented by Swati T @04 Dec 2018
                                        $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin:  8px 0px 0;" >
                                        <tr>
                                            <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                                Action Code
                                            </td>
                                            <td style="font-size:16px; color: #000; text-align:left;">
                                                ' . $value["action_code"] . '
                                            </td>
                                        </tr>
                                    </table>';
                                    $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
                                    <tr>    
                                        <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                            Group name
                                        </td>
                                        <td style="font-size:16px; color: #000; text-align:left;">
                                            '.$value["groupName"].'
                                        </td>
                                    </tr>
                                </table>';
                                $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin:  8px 0px 0; width:100%;" >
                                <tr>
                                    <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%;  vertical-align:top;">
                                        Audit Question
                                    </td>
                                    <td style="font-size:16px; color: #000; text-align:left;">
                                     ' . $value["audit_question"] . ' 
                                 </td>
                             </tr>
                         </table>';
                         if($value["comment"]!=''){
                            $newMsg .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 8px 0px 0; width:100%;" >
                            <tr>
                                <td style="font-size:16px; color: #00b3ec; font-weight: 600; text-transform: uppercase; width:26%; vertical-align:top;">
                                    Finding
                                </td>
                                <td style="font-size:16px; color: #000; text-align:left;">
                                  ' . $value["comment"].'
                              </td>
                          </tr>
                      </table>'; 
                  }
                  $newMsg .= $auditImage;
                  $group_values++;
              }
              $msg1 .= $newMsg;

          }
          $content .= $msg1;

          $content .= '<div style="page-break-after: always;"></div>';

          $content .= '<table border="0" cellpadding="0" cellspacing="0" width="" style="margin: 30px 0px;" >
          <tr>
            <td style="font-size:45px; color: #000; font-weight: bold; line-height: 40px">
                Thank you.<br><br><br>
            </td>
        </tr>
        <tr>
            <td>
                <p style="font-size:16px; color: #000;">
                   We love feedback, and yes, that also includes constructive criticism. If there is anything amiss or you are happy with this audit, and want you want to share it with us, please contact us:<br/><br/>
                   Customer care:<br/><br>
                   customercare@i-comply.co <br/>
                   833 229 1215 <br/><br/>

                   Please also consider completing a survey about your audit experience: <a herf="https://www.surveymonkey.com/r/DTHGP9D" target="_blank"> https://www.surveymonkey.com/r/DTHGP9D.</a>
                   <br><br>
               </p>
           </td>
       </tr>
   </table>';

   $content .= '<div style="page-break-after: always;"></div>';

   $content .= '<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
   <table cellpadding="0" cellspacing="0" width="100%" border=0 style="margin: 30px 0px; ">
    <tr>
        <td rowspan="4" style="font-size: 18px; color: #fff;">
         <p> <strong>iComply </strong> <br>
             South Jordan, Utah <br>
             84095
         </td>
         <td style="font-size: 18px; color: #fff; text-align:center;">
            <p>i-comply.co</p>
            <p>+1 833 229 1215</p>
        </td>
        <td>
            <img src="images/newlogo.png" alt="" style="width:100px">
        </td>
    </tr>
</table>';

$content .= '<htmlpagefooter name="MyFooter1">
<table width="100%" style="vertical-align: bottom; font-family: serif; font-size: 8pt; color: #000000; font-weight: bold; font-style: italic;">
    <tr>
        <td width="50%" align="left"><span style="font-weight: bold; font-style: italic; font-size:12px;">{DATE j-m-Y}</span></td>
        <td width="49%" align="right" style="font-weight: bold; font-style: italic;font-size:12px;">{PAGENO}/{nbpg}</td>
    </tr>
</table>
</htmlpagefooter>';

$content .= '</body>';   

    $mpdf = new mPDF('c', 'A4', '', '', 32, 25, 27, 25, 16, 13);
    $mpdf->writeHTML($content, 0); // All result from database write here
    //$mpdf->AddPage('','','','','','','','','','','','html_MyHeader2', '', 'html_MyFooter2', '', 0, 0, 0, 0);
    $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
    $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;
    $senderEmail = DEFAULT_EMAIL_ADDRESS;
    $message = "Please find the attachment ";
    
    $subject = "Audit Report";
    $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
    $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;
    if(empty($email)){
        if ($msg) {
            $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => (string)$msg);
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
                }
                }else{

                    $attachment = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname;                  

                    if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachment)) {
                        $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
                    } else {
                        $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
                    }
                }
            } else {
                $response = array('status' => BOOL_FALSE, 'message' => 'Data is not found');
            }
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Data is not in post format');
        }
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }


    public function getGapAnalysis(){
      Configure::write('debug',0);
      $response = array();
      if ($this->request->isPost() && !empty($this->request->data)) {
        $audits_id = $this->request->data['audits_id'];
        $clients_id = $this->request->data['clients_id']; 
        $email = $this->request->data['email'];
        App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));      
        //App::import('Vendor', 'mpdf', array('file' => 'mpdf' . DS . 'mpdf.php'));
        $this->loadModel('Audit');
        $this->loadModel('Client');
        $this->loadModel('User');
        $this->loadModel('Question');
        $this->loadModel('AuditGroupQuestionComments');
        $this->loadModel('AuditGroupComment');
        $this->loadModel('AuditGroupQuestion');
        $AuditDates = $this->Audit->find('all', array('conditions' => array('Audit.clients_id' => $clients_id, 'Audit.is_deleted' => 0), 'fields' => array('Audit.audit_date')));
        $scoreArr = array();
        $getArr = array();
        if($clients_id != null && $audits_id != null) {
            $getArr = $this->AuditGroupQuestion->getAuditsQuestionsArr($clients_id, $audits_id);
        }
        if(!empty($getArr)) {
            //$pdfname = "auditReportPdf" . time() . '.pdf';
            $i = 0;
            $contact_person_name = $this->Audit->find('all', array('conditions' => array('Audit.id' => $audits_id), 'fields' => array('Audit.contact_person_name')));
            foreach ($getArr as $auditID) {
                $auditData['Audit'] = $auditID['Audit'];
                $companyName = $auditID['Client']['company_name'];
                $clients_id = $auditID['Audit']['clients_id'];
                if (!empty($clients_id)) {
                    $getClientDetail = $this->Client->find('first', array('conditions' => array('Client.id' => $clients_id)));
                    if (!empty($getClientDetail)) {
                        $clientDetail['client_email'] = $getClientDetail['Client']['email'];
                        $clientDetail['client_contact'] = $getClientDetail['Client']['contact_name'];
                        $clientDetail['client_contact_name'] = $getClientDetail['Client']['client_name'];
                        $clientDetail['phone_number'] = $getClientDetail['Client']['phone_number'];
                        $auditData['clientDtail'] = $clientDetail;
                    } else {
                        $auditData['clientDtail'] = array();
                    }
                }
                $dataArr[0][0]['avgPercentage'] = '100';
                if (!empty($auditID['AuditGroup'])) {
                    foreach ($auditID['AuditGroup'] as $val) {
                        $groupArrID[] = $val['groups_id'];
                        $getCompyNScore = $this->AuditGroupQuestionComments->getAllComplyScore($val['groups_id'], $audits_id, $clients_id);
                        $AuditGroupCommentArr = $this->AuditGroupComment->find('all', array('conditions' => array('AuditGroupComment.groups_id' => $val['groups_id'], 'AuditGroupComment.audits_id' => $audits_id, 'AuditGroupComment.clients_id' => $clients_id, 'AuditGroupComment.is_deleted' => 0, 'AuditGroupComment.action' => array('NC','OB')), 'fields' => array('AuditGroupComment.comment,AuditGroupComment.action,AuditGroupComment.image,AuditGroupComment.groups_id')));

//                            echo "\n\n";
//                            pr($getCompyNScore);
//                            echo "\n---------------------------------------------\n";
//                            pr($AuditGroupCommentArr);
//                            echo "<hr>";
//                            pr($this->AuditGroupComment->getDataSource()->getLog(0,0));
                        $question = "";
                        if (!empty($getCompyNScore)) {
                            foreach ($getCompyNScore as $getCompyNScoreArr) {
                                //print_r($groupEndTime);
                                $queGrpID = !empty($getCompyNScoreArr['AuditGroupQuestionComments']['questions_id']) ? $getCompyNScoreArr['AuditGroupQuestionComments']['questions_id'] : 0;
                                $getQuestion = $this->Question->find('first', array('conditions' => array('Question.id' => $queGrpID)));

                                $question = !empty($getQuestion['Question']['question']) ? $getQuestion['Question']['question'] : "";
                                $dataArr['auditsId']= $getCompyNScoreArr['AuditGroupQuestionComments']['audits_id']; // by swati t
                                $dataArr['groupqueID']= $getCompyNScoreArr['AuditGroupQuestionComments']['id']; // by swati t
                                $dataArr['audit_question'] = $getQuestion['Question']['question'];
                                //$dataArr['percentage'] = $getCompyNScoreArr['AuditGroupQuestionComments']['percentage'];
                                $dataArr['comment'] = $getCompyNScoreArr['AuditGroupQuestionComments']['comment'];
                                $dataArr['created_date'] = $getCompyNScoreArr['AuditGroupQuestionComments']['created_date']; // by swati t
                                $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image']; // by swati t

                                $dataArr['image'] = $getCompyNScoreArr['AuditGroupQuestionComments']['image'];
                                $dataArr['action_code'] = $getCompyNScoreArr['AuditGroupQuestionComments']['action'];
                                $dataArr['groupName'] = $val['group_name'];
                                
//                                        $dataArr['percentage'] = $groupEndTime['AuditGroupComment']['percentage'];
                                //print_r($dataArr);
                                $scoreArr[] = $dataArr;
                            }

                            $this->loadModel('AuditPercentage');
                            $AuditPercentageArr = $this->AuditPercentage->find('all', array('conditions' => array('AuditPercentage.audits_id' => $audits_id, 'AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage !=' => ''), 'fields' => array('AuditPercentage.end_time', 'AuditPercentage.percentage', 'AuditPercentage.groups_id'), 'order' => array('AuditPercentage.groups_id ASC')));


                            $dataArr = $this->AuditPercentage->find("all", array(
                                "fields"     => array("AVG(AuditPercentage.percentage) AS avgPercentage"),
                                "conditions" => array('AuditPercentage.clients_id' => $clients_id, 'AuditPercentage.percentage >= ' => '0',
                                    'AuditPercentage.audits_id' => $audits_id)
                                ));
                            $auditData['complyScore1'] = array();
                            foreach ($AuditPercentageArr as $AuditPercentageNewArr) {
                                $groupInfo = $this->Audits->getAllGroupsByGroupId($AuditPercentageNewArr['AuditPercentage']['groups_id']);

                                $dataArr1['percentage'] = $AuditPercentageNewArr['AuditPercentage']['percentage'];
                                $dataArr1['end_time'] = $AuditPercentageNewArr['AuditPercentage']['end_time'];
                                $dataArr1['groupName1'] = $groupInfo[0]['full_name'];
                                $auditData['complyScore1'][] = $dataArr1;
                            }
                        }
                        if (!empty($AuditGroupCommentArr)) {
                            //print_r($AuditGroupCommentArr); exit;
                            //$scoreArrAudit = array();
                            foreach ($AuditGroupCommentArr as $AuditGroupCommentNewArr) {
                                // $groupID= $AuditGroupCommentNewArr['AuditGroupComment']['groups_id'];
                                //$groupName[0]['AuditGroup']['group_name'] = $this->AuditGroup->find('all',array('conditions'=>array('AuditGroup.groups_id'=>$groupID),'fields' => array('AuditGroup.group_name')));
                                $dataArr['comment'] = $AuditGroupCommentNewArr['AuditGroupComment']['comment'];
                                $dataArr['image'] = $AuditGroupCommentNewArr['AuditGroupComment']['image'];
                                $dataArr['action_code'] = $AuditGroupCommentNewArr['AuditGroupComment']['action'];
                                $dataArr['audit_question'] = "";
                                $dataArr['groupName'] = $val['group_name'];
                                $scoreArr[] = $dataArr;
                            }
                        }

                        $i++;
                    }
                    $auditData['complyScore'] = $scoreArr;
                } else {
                    $auditData['complyScore'] = $scoreArr;
                }
//                    echo '<br>'.__LINE__;
                /*print_r($auditData['complyScore']);
                echo "aaaaaaaaa";
                print_r($auditID); 
                exit;*/
                $i++;
                $scheduleDateArr = array();
                if (!empty($auditID['AuditGroupSchedule'])) {
                    foreach ($auditID['AuditGroupSchedule'] as $val1) {
                        $schedulArr[] = $val1['schedule_date'];
                    }
                    $auditData['scheduledates'] = $schedulArr;
                } else {
                    $auditData['scheduledates'] = array();
                }
            }

        }
        $usersId = $auditData['Audit']['users_id'];
        $userDetails = $this->User->find('first', array('conditions' => array('User.id' => $usersId)));
        $userEmail = $userDetails['User']['email'];
        $css = "<style>
        .fullPage{ background-colr: #322343; }
        @page{ background-colr: #FFF; } 
        .wrap{ padding: 70px; }
        body{margin:0; padding: 0; box-sizing: border-box;font-family: 'Open Sans', sans-serif;}
        .report-title{font-size: 34px; color: #000000; margin: 0;padding: 80px 0 0 0;}
        .gap-title{ font-size: 74px; font-weight: 600; margin: 0; color: #fff; }
        .standards{font-size: 24px; font-weight: 400; color: #fff;padding: 50px 0 200px 0;}
        .white-color{color: #fff;}
        .prepare-title{font-size: 14px; font-weight: 600; margin: 0;}
        .prepare-des p{margin: 0; font-size: 13px; font-weight: 300; line-height: 1.5}
        .thankyou-title{ padding : 10px; font-size: 36px; font-weight: bold;font-family: 'Open Sans Condensed', sans-serif; margin: 0 0 10px 0; color: #000;}
        .summery-title{ margin: 0; color: #e84b21; text-transform: uppercase; font-weight: 400; font-size:20px; padding: 30px 0 0 0;} 
        .thankyou-section{ width:750px; } 
        .thankyou-section p{ font-size: 12px; color: #000; margin: 0;}
        .gap-score-title{font-size: 36px; color: #000;font-weight: bold; text-align: center; }
        .gapscore-section{padding: 50px; text-align: center; }
        table{border-collapse:collapse;}
        table.gapscore-table{width: 100%; border: none; border-collapse: collapse; margin-bottom:10px; }
        table.gapscore-table-header{width: 100%; border: none; border-collapse: collapse;}
        table.gapscore-table th{background: #fa4e00; color: #fff; text-align: left; vertical-align: middle; padding: 2px 10px; font-weight: 400; font-size: 14px; text-transform: uppercase;}
        table.gapscore-table td{background: #f2f2f2; color: #000;vertical-align: middle; padding: 14px 10px;text-align: left; font-size: 13px; font-weight: 600; border-bottom: 5px solid #fff;}
        table.gapscore-table-header td{ color: #000;vertical-align: middle; padding: 14px 10px;text-align: left; font-size: 13px; font-weight: bold; border-bottom: 5px solid #fff;}
        .text-center{text-align: center;}
        table.gapscore-table td.gapscroe-num{ background: #dbe3e9; text-align: center;}
        table.gapscore-table td.average{ text-align: right;}
        table.gapscore-table td.average.gapscroe-num{ text-align: left;}
        .gap-report{padding:70px;}
        .gap-report-title{font-size: 36px; color: #000;font-weight: bold; margin: 0 0 30px 0;}
        .finding-title{ font-size: 36px; font-weight: 600; color: #000; margin: 0 10px 0px 0; text-align: center;}
        .gapaction-title{ color: #fa4e00; font-size: 16px; margin: 0; font-weight: 800;text-transform: uppercase;}
        table.gap-report-table{ width: 100%; border: none; font-size: 13px;}

        .thankyou-section-2{padding: 70px;}
        .thankyousection-title2{ font-size: 36px; color: #000; font-weight: 700; }
        .thankyou-section-2 p{font-size: 13px;}
        .testimonial-section{background: #000; padding:70px; color: #fff;}
        .quote-img{padding-top: 30px;}
        .testimonial-text{ color:#fff; font-size: 36px; font-style: italic; font-weight: 400; line-height: 1.8; padding: 55px 0;}
        .testimonial-dot{font-size: 40px; font-weight: 600;  line-height: 1;}
        .compliance{font-size: 14px; color: #e84c22; padding-top: 70px; display: block; text-transform: uppercase;}
        .customername{ font-size: 15px; font-style: italic; color:#fff; }
        .compliance-footer{ padding: 3px 40px; color: #f9c6c6; font-size: 13px; border-left: 1px solid #e46b48; border-right: 1px solid #e46b48; line-height: 1.8;}
        .compliance-redbg{ background: #e84c22; padding: 70px;}
        .compliance-front{ background: #e84b21; padding: 70px;}    
    </style>";
    $mpdf=new mPDF('', 'A4', '12', '', '0', '0', '0', '0');
// Gap Scores
    $content = '<table class="fullPage" width="820" bgcolor="#e84b21" border="0" align="center" cellspacing="0" cellpadding="0">
    <tbody>
        <tr>
          <td class="compliance-front">
            <table width="100%" border="0" bgcolor="#e84b21" cellspacing="0" cellpadding="0">
              <tbody>
                  <tr>
                      <td height="20" >&nbsp;</td>
                  </tr>
                  <tr>
                      <td><img src="images/compilancelogopdf.png" width="340" height="78" alt=""/></td>
                  </tr>
                  <tr>
                      <td height="130" >&nbsp;</td>
                  </tr>

                  <tr>
                      <td>
                        <h3 class="report-title">Report For</h3>
                    </td>   
                </tr> 

                <tr>
                  <td height="20" >&nbsp;</td>
              </tr>

              <tr>
                  <td>
                    <h2 class="gap-title">GAP ANALYSIS REPORT FOR '.strtoupper($auditData['Audit']['client_name']).'</h2>
                </td>   
            </tr>  

            <tr>
              <td height="60" >&nbsp;</td>
          </tr>
          <tr>
              <td>
                <div class="standards">'.$auditData['Audit']['audit_standards'].' </div>
            </td>   
        </tr>  

        <tr>
            <td height="450" >&nbsp;</td>
        </tr>

        <tr>
          <td>
             <table class="white-color" cellspacing="0" cellpadding="15" style="border: 1px solid #fff">
              <tbody>
                <tr>
                  <td valign="top" width="180" class="prepare-des">
                    <h6 class="prepare-title">Prepared for</h6>
                    <p>'.$auditData['clientDtail']['client_contact'].' </p>
                    <p>'.$auditData['clientDtail']['client_contact_name'].'</p>
                    <p>'.$auditData['clientDtail']['phone_number'].'</p>
                    <p>'.$auditData['clientDtail']['client_email'].' </p>
                </td>
                <td valign="top" class="prepare-des" style="border-left: 1px solid #fff;">
                    <h6 class="prepare-title">Dates:</h6>
                    <p>'.$auditData['Audit']['audit_date'].'</p>
                    <p><strong>Location of analysis:</strong> <span>'.$auditData['Audit']['client_address'].'</span></p>
                    <p><strong>Consultant name: </strong><span>'.$auditData['Audit']['auditer_name'].'</span></p>
                    <p><strong>Email:</strong> <span>'.$userEmail.'</span></p>
                    <p><strong>Web:</strong> <span>www.quality-assurance.com</span></p>
                </td>
            </tr>
        </tbody>
    </table>              
</td>
</tr>
</tbody>
</table>
</td>
</tr>    
</tbody>
</table>';
$mpdf->AddPage(); // Adds a new page in Landscape orientation
/*Adding Css Only*/
$mpdf->WriteHTML($css);
$mpdf->WriteHTML($content);
// Gap Scores
$content = '
<div class="wrap" >
    <table>
        <tr><td height="30" >&nbsp;</td></tr>  
        <tr>
            <td class="thankyou-section" style="">
              <h1 class="thankyou-title">Thank you for letting us perform this Gap Analysis for your organization.</h1>
          </td>   
      </tr>     
      <tr><td height="30" >&nbsp;</td></tr>    
      <tr><td height="30" >
        <h4 class="summery-title">SUMMARY</h4>
    </td></tr>
    <tr><td>    ' .str_replace("\n", "<br />", $auditData["Audit"]["audit_summary"]). ' </td></tr>
    <tr><td height="30" >&nbsp;</td></tr>    
    <tr><td height="30" >
        <h4 class="summery-title">SCOPE OF THE GAP ANALYSIS</h4>
    </td></tr>
    <tr><td> '.$auditData['Audit']['audit_scope'].'</td></tr>
    <tr><td height="30" >&nbsp;</td></tr>    
    <tr><td height="30" >
        <h4 class="summery-title">STANDARDS</h4>
    </td></tr>
    <tr><td> '.$auditData['Audit']['audit_standards'].'</td></tr>
    <tr><td>&nbsp;</td></tr>
    <tr><td>&nbsp;</td></tr>
    <tr><td>&nbsp;</td></tr>
</table></div>
';
$mpdf->AddPage(); // Adds a new page in Landscape orientation
$mpdf->WriteHTML($content);
// Gap Scores
$gapScore = $auditData['complyScore1'];
$gapScoreRow = array();
$paged =1;
$pagedCounter = 1;
foreach($gapScore as $values){
    if($pagedCounter == 15 or ($pagedCounter/15 > 1 && $pagedCounter%15 == 0)){
        $paged++;
    }
    $gapScoreRow[$paged][]= "<tr><td>".$values['groupName1']."</td><td class='gapscroe-num'>".$values['percentage']."</td></tr>";
    $pagedCounter++;
}
$averageComiplationScorePercent = round($dataArr[0][0]['avgPercentage'],2);
foreach($gapScoreRow as $key=>$values){
    $averageComiplationScore = '';
    if($key == $paged ){ 
       $averageComiplationScore = "<tr>
       <td class='average'><strong>Average Compliance Score</strong></td>
       <td class='average gapscroe-num'><strong>".$averageComiplationScorePercent."</strong></td>
   </tr>"; 
}

$content = '<div class="wrap" ><table class="gapscore-table-header">
<tr>
  <td align="left"  class="gapscore-section">
    <span class="gap-score-title">Gap Scores</span>
</td>
</tr>  
</table>
<br/>
<table class="gapscore-table">                
    <thead>
        <tr>
          <th>GROUP NAME</th>
          <th width="90">COMPLIANCE<br>SCORE (%)</th>
      </tr>
  </thead>                
  <tbody>
   '.implode("",$values).$averageComiplationScore.'
</tbody>
</table></div>';
$mpdf->AddPage(); // Adds a new page in Landscape orientation
$mpdf->WriteHTML($content);
}
// Gap Report
$complyScore = $auditData['complyScore'];
$gapScoreRow = "";
$paged =1;
$pagedCounter = 0;
foreach($complyScore as $values){
    if(empty($values['action_code'])){
        continue;
    }    
    $pagedCounter++;
    if($values['action_code'] =='OB'){ $actionCode = "Observation"; }
    if($values['action_code'] =='NC'){ $actionCode = "Non-Conformance"; }
    $complyScoreRow[$paged][]= "<br/><h3 class='finding-title'>Finding ". $pagedCounter ." </h3>   
     <table class='gap-report-table'>
        <tbody>
          <tr>
            <td class='gapaction-title' width='150px'>ACTION CODE</td>
            <td>".$actionCode."</td>
        </tr>
        <tr>
            <td class='gapaction-title'>CLAUSE</td>
            <td>".$values['groupName']."</td>
        </tr>
        <tr>
            <td class='gapaction-title'>QUESTION</td>
            <td>".$values['audit_question']."</td>
        </tr>
        <tr>
            <td class='gapaction-title'>FINDING</td>
            <td>".$values['comment']."</td>
        </tr>
    </tbody>
  </table>";
    
    
    
if($pagedCounter%4 == 0 ){
    $paged++;
}
}
foreach($complyScoreRow as $key=>$values){
    $content = '<div class="wrap" ><table class="gapscore-table-header">
    <tr>
        <td class="gap-report">
            <h2 class="gap-report-title">Gap report</h2>

        </td>
    </tr></table>
    '.implode("",$values).'
</div>';
    $mpdf->AddPage(); // Adds a new page in Landscape orientation
    $mpdf->WriteHTML($content);
}
// ThankYou Page
$content = '<div class="wrap" >
<table class="gapscore-table-header">
  <tr>
    <td class="thankyou-section-2">
      <h2 class="thankyousection-title2">Thank you.</h2>    
  </td></tr></table>   

  <table class="gap-report-table">  
    <tr>
        <td>
            <p style="padding:20px">We love feedback, and yes, that also includes constructive criticism. If there is anything amiss or you are happy
                with this audit, and want you want to share it with us, please contact us:</p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Customer care:</p>
            </td>
        </tr>
        <tr>
            <td>
                <ul style="list-style-type:disc;padding:20px">
                    <li>admin@quality-assurance.com</li>
                    <li>877 238 5855</li>
                </ul>
            </td>
        </tr>
    </table></div>';
$mpdf->AddPage(); // Adds a new page in Landscape orientation
$mpdf->WriteHTML($content);
// Secoand Last Page of document
$content = '
<table height="1200px">
    <tr>
        <td class="testimonial-section">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
              <tbody>
                <tr>
                  <td class="quote-img"><img src="images/quotepdf.jpg" width="75" height="65" alt=""/></td>
              </tr>
              <tr>
                  <td class="testimonial-text">
                    We love everything about your team. Everyone was genuine and informative from the start…sharp as a razor.  I originally thought it was going to be like pulling teeth, but on the contrary, we had a pleasurable experience. Good pricing and great service. You guys are awesome. Thank you for all your help! 
                </td>
            </tr>
            <tr>
                <td class="testimonial-dot testimonial-text">.</td>
            </tr>

            <tr>
                <td height="150px">
                    &nbsp;
                </td>
            </tr>
            <tr>
                <td>
                    <span class="compliance">COMPLIANCEHELP CUSTOMER:  </span> <br/>
                    <span class="customername">Jacques Antikadjian, President, Metrix Systems 
                    </span>
                </td>
            </tr>

        </tbody>
    </table>
</td>
</tr></table>';
$mpdf->AddPage(); // Adds a new page in Landscape orientation
$mpdf->WriteHTML($content);
// Last Page of document
$content = '
<div class="compliance-redbg">
    <table >
     <tr>
        <td class="compliance-redbg" height="1030px" >
           <table width="100%" border="0" cellspacing="0" cellpadding="0">
              <tbody>
                  <tr>
                    <td colspan="2" height="800px">&nbsp;</td>
                </tr>
                <tr>
                  <td align="left" valign="top" width="40%" class="compliance-footer">Compliancehelp Consulting, LLC<br>
                    South Jordan<br>
                    Utah 84095
                </td>
                <td align="left" valign="top" width="40%" class="compliance-footer">Quality-assurance.com<br>
                    t. 877 238 5855
                </td>                  
            </tr>
        </tbody>
    </table>  
</td>
</tr></table></div>';
    $mpdf->AddPage(); // Adds a new page in Landscape orientation
    $mpdf->WriteHTML($content);
    //$mpdf->Output('GapAnalysis.pdf', 'D');
    //getGapAnalysis
    //$mpdf->WriteHTML($html);
    //$mpdf->Output();
    //exit;
    //==============================================================
    //==============================================================
    //==============================================================
    $pdfname = "GapAnalysis" . time().".pdf";
    //$mpdf->AddPage('','','','','','','','','','','','html_MyHeader2', '', 'html_MyFooter2', '', 0, 0, 0, 0);
    // $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
    $msg = SITE_LINK . '/img/pdf_files/' . $pdfname;
    $senderEmail = DEFAULT_EMAIL_ADDRESS;
    $message = "Please Find the attachment";
    $subject = "Gap Analysis";
    $mpdf->Output($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname, 'F');
    $attachment = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/pdf_files/" . $pdfname;
    $msg = SITE_LINK . '/img/pdf_files/' . $pdfname; 
    if(empty($email)){
        if ($msg) {
         $response = array('status' => BOOL_TRUE, 'message' => 'found pdf', 'data' => (string)$msg);
     } else {
        $response = array('status' => BOOL_FALSE, 'message' => 'No pdf found');
    }
    }else{
        if ($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachment)) {
            $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
        } else {
            $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
        }
    }
    }
    else {
        $response = array('status' => BOOL_FALSE, 'message' => 'Data is not in post format');
    }
    $this->set('result', $response);
    $this->set('_serialize', array('result'));
    $this->_render();
}




public function sendBarChartTOEmail(){
    Configure::write('debug',0);
    if ($this->request->isPost() && !empty($this->request->data)) {
        $email = $this->request->data['email'];
        $img = $this->request->data['img']; 
        $barChartHeading = $this->request->data['subject']; 
        $barChartFooter = $this->request->data['message']; 
        $senderEmail = DEFAULT_EMAIL_ADDRESS;
        $data = 'data:image/png;base64,'.$img;
        list($type, $data) = explode(';', $data);
        list(, $data)      = explode(',', $data);
        $data = base64_decode($data);
        $pdfname = time().".png";
        file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/". $pdfname, $data);   
        header('Content-type: image/png');
        $path = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/". $pdfname;
        // Create Image From Existing File
        $jpg_image = imagecreatefrompng($path);
        // Allocate A Color For The Text
        $black = imagecolorallocate($jpg_image, 0, 0, 0);
        // Set Path to Font File
        $font = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/fonts/opensans-regular-webfont.ttf";
        $text = $barChartHeading;
        imagettftext($jpg_image, 17, 0, 160, 25, $black, $font, $text);

        $text = $barChartFooter;
        imagettftext($jpg_image, 17, 0, 300, 450, $black, $font, $text);
        imagettftext($jpg_image, 17, 0, 160, 470, $black, $font, '');
        

        imagepng($jpg_image, $path);

        imagedestroy($jpg_image);
        header('Content-type: text/html');
        $message = "$barChartHeading";
        $attachmentFile = $_SERVER['DOCUMENT_ROOT'] . "/app/webroot/img/". $pdfname;        
        $subject = $barChartHeading;
        if($this->Email->sendMailContent($email, $senderEmail, $subject, $message, $attachmentFile)) {
            $response = array('status' => BOOL_TRUE, 'message' => 'Email sent successfully', 'data' => 'Email sent successfully');
        }else{
            $response = array('status' => BOOL_FALSE, 'message' => 'Email not sent. Please try again!');
        }
    }else{
        $response = array('status' => BOOL_FALSE, 'message' => 'Data is not in Correct Format .');
    }
    $this->saveLogBeforeRetruning($response);
    $this->set('result', $response);
    $this->set('_serialize', array('result'));
    $this->_render();
}


public function markAuditComplete(){
     Configure::write('debug',0);
     if ($this->request->isPost() && !empty($this->request->data)) {
        $this->loadModel('AuditGroupQuestionComments');
        $this->request->data['AuditGroupQuestionComments']['id'] = Sanitize::escape($this->request->data['id']);
        $this->request->data['AuditGroupQuestionComments']['date_completed'] = Sanitize::escape($this->request->data['date']);

        if ($this->AuditGroupQuestionComments->save($this->request->data['AuditGroupQuestionComments'])) {
            $response = array('status' => 1, 'data' => "Saved successfully" );
        } else {
            $response = array('status' => '0', 'message' => "Some Error Occured");
        }

        $allHeaders = getallheaders();
        $this->saveLogBeforeRetruning($allHeaders);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
}



public function addAuditorQuestion(){
    Configure::write('debug',0);
    if ($this->request->isPost() && !empty($this->request->data)) {
        $groupId = Sanitize::escape($this->request->data['groups_id']);
        $clientId = Sanitize::escape($this->request->data['clients_id']);
        $audits_id = Sanitize::escape($this->request->data['audits_id']);
        $question = Sanitize::escape($this->request->data['question']);
        $userId = Sanitize::escape($this->request->data['user_id']);
        $this->loadModel('questions');
        $lastCreated = $this->questions->find('first', array(
            'order' => array('questions.id' => 'desc'),
            'limit' => 1, 
            ));
        $this->request->data['questions']['sort'] = $lastCreated['questions']['id'];
        $this->request->data['questions']['question'] = $question;
        $this->questions->save($this->request->data['questions']);
        $questionId = $this->questions->getInsertID();
        $this->loadModel('AuditGroupQuestion');
        $haveRecords = $this->AuditGroupQuestion->find('first', array(
            'conditions' => array('AuditGroupQuestion.audits_id' =>  $audits_id, 'AuditGroupQuestion.clients_id' => $clientId, 'AuditGroupQuestion.groups_id' => $groupId),
            'limit' => 1, 
            ));
        if(count($haveRecords)>0){
            $this->request->data['AuditGroupQuestion']['audits_id'] = $audits_id;
            $this->request->data['AuditGroupQuestion']['clients_id'] = $clientId;
            $this->request->data['AuditGroupQuestion']['groups_id'] = $groupId;
            $this->request->data['AuditGroupQuestion']['questions_id'] = $questionId;
            $this->request->data['AuditGroupQuestion']['users_id'] = $this->loginUserId;
            $this->request->data['AuditGroupQuestion']['status'] = 1;
            $this->request->data['AuditGroupQuestion']['question'] = $question;                
            $this->AuditGroupQuestion->save($this->request->data['AuditGroupQuestion']);
        }
        $this->loadModel('GroupQuestion');
        $this->request->data['questions']['question'] = $questionId;
        $this->request->data['GroupQuestion']['questions_id'] = $questionId;
        $this->request->data['GroupQuestion']['groups_id'] = $groupId;
        $this->request->data['GroupQuestion']['clients_id'] = $clientId;
        $this->request->data['GroupQuestion']['audit_id'] = $audits_id;
        $this->GroupQuestion->save($this->request->data['GroupQuestion']);
        $this->loadModel('AuditGroupQuestionComment');
        $this->request->data['AuditGroupQuestionComment']['audits_id'] = $audits_id;
        $this->request->data['AuditGroupQuestionComment']['groups_id'] = $groupId;
        $this->request->data['AuditGroupQuestionComment']['clients_id'] = $clientId;
        $this->request->data['AuditGroupQuestionComment']['questions_id'] = $questionId;
        $this->AuditGroupQuestionComment->save($this->request->data['AuditGroupQuestionComment']);
        $scoreArr['questionId'] = $questionId;       
    }
    if (!empty($scoreArr)) {
        $response = array('status' => 1, 'data' => $scoreArr);
    } else {
        $response = array('status' => '0', 'message' => "No data found");
    }
    $allHeaders = getallheaders();
    $this->saveLogBeforeRetruning($allHeaders);
    $this->set('result', $response);
    $this->set('_serialize', array('result'));
    $this->_render();
}

    public function locationListing($clientId) {  
        Configure::write('debug',0);
        $this->layout = 'client/inner';   
        $this->set('id', $clientId);
        $this->set('title_for_layout', 'Audit Listing');
        $this->loadModel('clientSubOffice');
        $clientListing = $this->UtilityFunction->getSubOfficeListingForClientNew($clientId);      
        $buildTree = $this->UtilityFunction->buildTree($clientListing);
        $this->set('result', $buildTree);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    // New Web services for Ipad @vaibhav
    
    public function recursiveOptionFieldsFrontEnd($leadId="") {             
        $clientListing = $this->UtilityFunction->getSubOfficeListingForClient($leadId,$parentId = NULL, $condition=true);          
        $buildTree = $this->UtilityFunction->buildTree($clientListing);
        $officeOptions = $this->UtilityFunction->recursiveOptionFields($buildTree);    
        $this->set('result', $officeOptions);
        $this->set('_serialize', array('result'));
        $this->_render();      
    }
    
    
    public function getOfficeHelper($officesDetails) {
        foreach ($officesDetails as $key => $value) {
            $auditTypes = json_decode($value->audit_type);
            $isovalue = '';
            foreach ($auditTypes as $key1 => $auditType) {
                $isovalue .= getIsoNameById($auditType) . '  ,  ';
            }
            $data[] = $value;
            $data[$key]->audit_type = rtrim($isovalue, ',');
        }
        return $data;
    }
    
    
    public function getIsoNameById($auditTypeId){
        $this->loadModel('AuditType');
        
        $data = $this->AuditType->find('all', array(
            'conditions' => array('AuditType.id' =>  $auditTypeId),          
        )); 

        return $data[0]['AuditType']['audit_name'];
    }
    
    
    
//        public function subOfficesListingApi($clientId="",$auditorId="") {  //commented by vaibhav 17/1/19
////        Configure::write("debug",2);
//         $this->loadModel('clientSubOffice');
//         
//         if ($this->request->isPost() && !empty($this->request->data)) {
//            $clientId = @$this->request->data['client_id'];
//            $auditorId = @$this->request->data['auditor_id'];            
//         }
//         
//         
//         
//         $clientSubOfficeList = $this->clientSubOffice->find('all', array(
//            'conditions' => array(
//                'clientSubOffice.clients_id' =>  $clientId, 
////                'clientSubOffice.is_active' => 1,
//                'clientSubOffice.auditor_id' => $auditorId),          
//            )); 
//         
//        foreach ($clientSubOfficeList as $subOffices) {
//            $data[] = array_shift($subOffices);
//        }     
//         
//        if($clientSubOfficeList){
//            $response = array('status' => 1, 'data' => $data);
//        }else{
//            $response = array('status' => 0, 'data' => "no data available");
//        }
//         
//        
//        $this->set('result', $response);
//        $this->set('_serialize', array('result'));
//        $this->_render();
//    }

    public function subOfficesListingApi($clientId="",$auditorId="") {  
//        Configure::write("debug",2);
         $this->loadModel('clientSubOffice');        
         
         if ($this->request->isPost() && !empty($this->request->data)) {
            $clientId = @$this->request->data['client_id'];
            $auditorId = @$this->request->data['auditor_id'];            
         }
         
         $clientSubOfficeList = $this->clientSubOffice->find('all', array(
            'conditions' => array(
                'clientSubOffice.clients_id' =>  $clientId, 
//                'clientSubOffice.is_active' => 1,
                'clientSubOffice.auditor_id' => $auditorId),          
            )); 
         
//        foreach ($clientSubOfficeList as $subOffices) {
//            $data[] = array_shift($subOffices);
//        }     
         
        foreach ($clientSubOfficeList as $key => $subOffices) {            
            $auditTypes = json_decode($subOffices['clientSubOffice']['audit_type']);
            $isovalue = '';
            foreach ($auditTypes as $key1 => $auditType) {
                $isovalue .= $this->getIsoNameById($auditType) . '  ,  ';
            }
            $data[] = $subOffices['clientSubOffice'];
            $data[$key]['audit_type'] = rtrim($isovalue, ' ,');
          
        }      

        if($clientSubOfficeList){
            $response = array('status' => 1, 'data' => $data);
        }else{
            $response = array('status' => 0, 'data' => "no data available");
        }
         
        
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();
    }
    
    
    
    public function subOfficesAuditListingApi() {
//        echo "asdf"; die;
        
//        $encodedClientId=nu,$encodedGroupId = null, $encodedOfficeId = null
       
        $response = array();
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);  
        
        $encodedClientId = $input_data['clientId'];
        $encodedGroupId = $input_data['groupId'];
        $encodedOfficeId = $input_data['officeId'];      

        
        if (!empty($encodedClientId)) {
            $this->loadModel('Audit');
            $clientId = $encodedClientId;            
            if(empty($encodedOfficeId)){
                $conditions = array( 'Audit.is_deleted' => BOOL_FALSE, 'Audit.clients_id' => $clientId );
            }else{
                $officeId = $encodedOfficeId;  
                $conditions = array( 'Audit.process_id' => $officeId, 'Audit.is_deleted' => BOOL_FALSE, 'Audit.clients_id' => $clientId );   
            }                       
            $auditData =  $this->Audit->find('all', array(
             'conditions' => $conditions,
             'fields' => array('Audit.id', 'Audit.process_id', 'Audit.clients_id', 'Audit.client_name', 'Audit.audit_name', 'Audit.audit_date', 'Audit.auditer_name', 'Audit.is_active', 'Audit.created_date'),
            ));
            $clientListing = $this->UtilityFunction->getSubOfficeListingForClient($clientId);
            $buildTree = $this->UtilityFunction->buildTree($clientListing);      
            $officeOptions = $this->UtilityFunction->buildTreeArrow ($buildTree);            
            $officeId = $encodedOfficeId;            
            $data['officeId'] = $officeId;
            $data['officeOptions'] = $officeOptions;
            $data['auditData'] = $auditData;
            $data['clientID'] = $clientId;  
            $response = array('status' => 1, 'data' => $data);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        } else {
            $this->Session->setFlash("Unauthorized access", 'error');
            $this->redirect($this->referer());
        }

   
    }
    
    public function subOfficesCreateAuditApi($clientId,$officeId = null) {    
        $officeId = !empty($officeId) ? $officeId : 0;          
        
        $this->uses =array('clientSubOffice','Client','Group','AuditGroup','GroupSetClient','User','Audit','AuditGroupSchedule');
          
        $clientSubOffice = $this->clientSubOffice->find('first', array('conditions' => array('clientSubOffice.clients_id' => $clientId,'clientSubOffice.id' => $officeId)));
        if(count($clientSubOffice) > 0){
            $clientSubOfficeDefaultId = $clientSubOffice['clientSubOffice']['group_set_id'];
            $this->request->data['Audit']['contact_person_name'] = $clientSubOffice['clientSubOffice']['contact_name'];
            $this->request->data['Audit']['contact_detail'] = $clientSubOffice['clientSubOffice']['cell_phone'];
            $this->request->data['Audit']['audit_name'] = $clientSubOffice['clientSubOffice']['city'];
            $this->request->data['phone_number'] = $clientSubOffice['clientSubOffice']['organization_phone'];
        }else{
            $clientSubOfficeDefaultId = 0;
        }  
      
        $client_name = $this->Client->find('first', array('conditions' => array('Client.id' => $clientId), 'fields' => array('Client.client_name')));
        if($officeId == 0 ){
            $conditions = array('Group.clients_id' => $clientId, 'Group.is_deleted' => 0, 'Group.is_active' => 1);
        }else{
            $clientSubOffice = $this->GroupSetClient->find('first', array('conditions' => array('GroupSetClient.id' => $clientSubOfficeDefaultId)));
            $groupIds = $clientSubOffice['GroupSetClient']['group_ids'];
            $groupIdsArray = explode(",", $groupIds);
            $conditions = array('Group.id' => $groupIdsArray, 'Group.is_deleted' => 0, 'Group.is_active' => 1);
        }       

        $group_name = $this->Group->find('list', array('conditions' => $conditions, 'fields' => array('Group.id', 'Group.full_name')));
        /* By Deepak Upadhyay add office for an audit */
        $clientListing = $this->UtilityFunction->getSubOfficeListingForClient($clientId);        
        $buildTree = $this->UtilityFunction->buildTree($clientListing);
        $officeOptions = $this->UtilityFunction->recursiveOptionFields($buildTree,0,$officeId);         
        /* End */
     
        $GroupSetClient = $this->GroupSetClient->find('list', array('conditions' => array('GroupSetClient.client_id' => $clientId, 'GroupSetClient.status' => 1)));
        $type = 'list';
        $conditions = array('User.is_deleted' => BOOL_FALSE, 'User.role_id !=' => ADMIN_ROLE_ID, 'User.is_active' => BOOL_TRUE);
        $fields = array('id', 'name');
        $contain = NULL;
        $order = array('User.created' => 'ASC');
        $group = NULL;
        $recursive = 0;
        $auditorList = $this->User->getUserData($type, $conditions, $fields, $contain, $order, $group, $recursive);
        $data['clientSubOfficeDefaultId'] = $clientSubOfficeDefaultId;
        $data['clientName'] = $client_name;
        $data['groupName'] = $group_name;
        $data['officeOptions'] = $officeOptions;
        $data['GroupSetClient'] = $GroupSetClient;
        $data['auditorList'] = $auditorList;        
        $this->set('result', $data);
        $this->set('_serialize', array('result'));
        $this->_render();

        if ($this->request->is('post') || $this->request->is('put')) {
            if (!empty($this->request->data)) {             
                $clientId = $this->request->data['Audit']['clients_id'];
                $this->request->data['Audit']['clients_id'] = $this->Encryption->decrypt($clientId);
                $this->request->data['Audit']['audit_date'] = date('Y-m-d', strtotime($this->request->data['Audit']['date'][0]));
                $this->request->data['Audit']['group_set_id'] = $this->request->data['Audit']['GroupSets'];
                if ($this->Audit->save($this->request->data['Audit'])) {
                    $lastInsertedAuditId = $this->Audit->getLastInsertID();
                    $count = count($this->request->data['Audit']['date']);
                    for ($i = 0; $i < $count; $i++) {
                        if(empty($this->request->data['Audit']['date'][$i]) || empty($this->request->data['Audit']['starttime'][$i]) || empty($this->request->data['Audit']['starttime'][$i])){
                            continue;
                        }
                        $fields['schedule_date'] = date('Y-m-d', strtotime($this->request->data['Audit']['date'][$i]));          
                        $fields['start_time'] = $this->request->data['Audit']['starttime'][$i];
                        $fields['finish_time'] = $this->request->data['Audit']['endtime'][$i];
                        $fields['audits_id'] = $lastInsertedAuditId;
                        $this->AuditGroupSchedule->create();
                        $this->AuditGroupSchedule->save($fields);
                    }
                    
                    if(!empty($this->request->data['Audit']['GroupSets'])){
                        $groupSetId = $this->request->data['Audit']['GroupSets'];                        
                        $GroupSetClient = $this->GroupSetClient->find('first', array('conditions' => array('GroupSetClient.id' => $groupSetId)));
                        $GroupSetClientArray = explode(",",$GroupSetClient['GroupSetClient']['group_ids']);
                        foreach($GroupSetClientArray as $key => $values){
                            $this->request->data['Audit']['Group'][] = $values;
                        }
                    }

                    $countGroup = count($this->request->data['Audit']['Group']);
                    for ($j = 0; $j < $countGroup; $j++) {
                        $getGroupName = $this->Group->find('first', array('conditions' => array('Group.id' => $this->request->data['Audit']['Group'][$j]), 'fields' => array('Group.full_name')));
                        $grpArr['audits_id'] = $lastInsertedAuditId;
                        $grpArr['groups_id'] = $this->request->data['Audit']['Group'][$j];
                        $grpArr['group_name'] = $getGroupName['Group']['full_name'];
                        $this->AuditGroup->create();
                        $this->AuditGroup->save($grpArr);
                    }

                    /* Set Notification */

                    $getUserDetail = $this->Users->getUserDetail($this->request->data['Audit']['users_id']);
                    if (!empty($getUserDetail)) {
                        $notificationArray = array(
                            'users_id' => !empty($getUserDetail['User']['id']) ? trim($getUserDetail['User']['id']) : ' ',
                            'deviceToken' => !empty($getUserDetail['User']['apn_device_token']) ? trim($getUserDetail['User']['apn_device_token']) : NULL,
                            'type' => 'Assign Audit',
                            'message' => "You have been assigned a new audit."
                            );
                     
                        $Notification = $this->UtilityFunction->setNotifications($notificationArray);

                        if (!empty($Notification)) {
                            $this->Session->setFlash("Audit created sucessfully", 'success');
                       
                            $officeId = $this->request->data['Audit']['office_id'];
                            $officeId = $this->Encryption->decrypt($officeId);                         
                            if($officeId == 0 ){
                                $this->redirect(array('controller' => 'managements', 'action' => 'auditListing', $this->Encryption->encrypt(trim($this->request->data['Audit']['clients_id']) ? trim($this->request->data['Audit']['clients_id']) : 0), 'ext' => URL_EXTENSION, 'admin' => TRUE));
                            }else{
                                $queryString = $this->Encryption->encrypt($this->request->data['Audit']['clients_id'])."/".$this->Encryption->encrypt(0)."/".$this->Encryption->encrypt($officeId);
                                $this->redirect("/admin/managements/auditListing/$queryString"); 
                            }                            
                        }
                    }
                    /* End of the code */
                } else {
                    $this->Session->setFlash("Audit could not be created", 'error');
                }
            } else {
                $this->Session->setFlash("Please provide valid data and try again", 'error');
            }
        } 
        
        $this->set('result', $data);
        $this->set('_serialize', array('result'));
        $this->_render();
    } 
    
     public function auditPushNotification() {
        $this->loadModel("Audit");
        $auditLists = $this->Audit->find('all', array('conditions' => array('Audit.done_by_client' => BOOL_FALSE)));
        $currentDate = date("Y-m-d");
        /* pushnotification sending using cron @vaibhav */
        foreach ($auditLists as $key => $auditList) {
            $auditorId = $auditList['Client']['auditor_id'];            
            $systemAdminId = $this->UtilityFunction->getSystemAdminId($auditorId);
            $token = $this->UtilityFunction->getNotificationTokenByAuditorId($auditorId);
            foreach ($auditList['AuditGroupSchedule'] as $key => $value) {               
               $priviousDate = date('Y-m-d', strtotime('-1 day', strtotime($value ['schedule_date'])));               
               if ($priviousDate == $currentDate) {
                    $message = "Your Audit Location: " . $auditList['Audit']['audit_name'] . " has been Scheduled on " . $value['schedule_date'] . ".\n Client Name: " . $auditList['Client']['client_name'];
                    $notificationId = $this->UtilityFunction->saveCustomNotification($systemAdminId,1,$message,"Audit reshedule Notification");   
                    $senderIds[] = $auditorId;         
                    $this->UtilityFunction->sendCustomNotification($senderIds,$notificationId);                     
                    $this->UtilityFunction->sendPushNotifications($token, $message);
                }
            }                   
            $oneMonthAgo = date('Y-m-d', strtotime('30 day', strtotime($value ['schedule_date'])));             
            if($oneMonthAgo == $currentDate){
                $this->Audit->updateAll(array('Audit.done_by_client' => BOOL_TRUE), array('Audit.id' => $auditList['Audit']['id']));
            }
            
        }
        /* end @vaibhav */        
        /* Audit Completed functionality automatically changed status when client not change his status after one month @vaibhav */
        /* end @vaibhav */       
    }
    
    /* request payment for admin*/
     public function requestForPayment() {
        Configure::write('debug', 2);
        if ($this->request->isPost() && !empty($this->request->data)) {
            $auditId = $this->request->data['audits_id'];
            $auditData = $this->UtilityFunction->getAuditDetailById($auditId);

            $auditorName = $this->UtilityFunction->getUserNameById($auditData['Audit']['users_id']);
            $msg = "Payment request from " . $auditorName . " for Audit Name :" . $auditData['Audit']['audit_name'];
            $type = "Request for Payment";
            $notificationId = $this->UtilityFunction->saveCustomNotification($auditData['Audit']['users_id'], AUDITOR_ROLE_ID, $msg, $type);
 
            $assignSubAdminIds = $this->UtilityFunction->getSubAdminIdByAuditorId($auditData['Audit']['users_id']);
            $system_admin_id[] = $auditData['Audit']['system_admin_id'];
            $senderIds = array_merge($assignSubAdminIds, $system_admin_id);
            $result = $this->UtilityFunction->sendCustomNotification($senderIds, $notificationId);
            
            if($result){
                 $response = array('status' => '1', 'data' => 'Request Sent sucessfully.', 'message' =>  'Request Sent sucessfully.');
            }else{
                 $response = array('status' => '0', 'data' => 'Request Sent faild.', 'message' =>  'Request Sent faild.');
            }
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }
    
    /* leave request */
     public function leaveRequest() {
        Configure::write('debug', 2);        
        $this->loadModel("Leave");        
        $response = array();
        $input = trim(file_get_contents('php://input'));
        $input_data = json_decode($input, true);         
        $reasons = $input_data['reason'];
        $users_id = $input_data['auditor_id'];
        $dates = $input_data['dates'];   
        if ($dates) {
            foreach ($dates as $key => $value) {
                $data['Leave']['users_id'] = $users_id;
                $data['Leave']['reasons'] = $reasons;
                $data['Leave']['date'] = $value;
                $this->Leave->create();
                $this->Leave->save($data);
            }            
            $response = array('status' => '1', 'data' => 'Data Save sucessfully.', 'message' => 'Data Save sucessfully.');
        }else{
            $response = array('status' => '0', 'data' => 'Request Sent faild.', 'message' => 'Request Sent faild.');
        }      
        $this->saveLogBeforeRetruning($response);
        $this->set('result', $response);
        $this->set('_serialize', array('result'));
        $this->_render();  
    }

    public function getAuditorNotifications() {
//        Configure::write("debug", 2);
        $this->loadModel("Notification");
        $auditorId = @$this->request->data['id'];
        if (empty($auditorId)) {
            $response = array('status' => false, 'data' => 'Not Found');
        } else {
            $conditions = array(
                'Notification.status !=' => DELETE_NOTIFICATION_ID,
                'Notification.user_id' => $auditorId,
            );
            $this->Paginator->settings = array(
                'Notification' => array(
                    'joins' => array(
                        array(
                            'table' => 'push_notifications',
                            'alias' => 'PushNotification',
                            'type' => 'inner',
                            'conditions' => array('PushNotification.id = Notification.notification_id')
                        ),
                    ),
                    'conditions' => @$conditions,
                    'fields' => array('PushNotification.*', 'Notification.*'),
                    'order' => array('Notification.created_at' => 'DESC'),
                    'limit' => 1000,
                    'contain' => NULL,
                    'recursive' => 0
            ));
            $result = $this->Paginator->paginate("Notification");   
            $profilePic = $this->UtilityFunction->getUserProfile($auditorId);
            foreach ($result as $key => $value) {
                $response['PushNotification'][] = $value['PushNotification'];
                $response['User'] = $profilePic;
            }
            
//            echo "<pre>";
//            print_r($response);
//            die;
            
            $response = array('data' => !empty($response) ? $response : "Record Not Found", 'status' => 1);
            $this->saveLogBeforeRetruning($response);
            $this->set('result', $response);
            $this->set('_serialize', array('result'));
            $this->_render();
        }
    }

}
