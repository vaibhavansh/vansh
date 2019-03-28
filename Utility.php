<?php

class Core_Models_Utility {
    static function ismobile() {
        $is_mobile = '0';

    if(preg_match('/(android|up.browser|up.link|mmp|symbian|smartphone|midp|mozi|wap|phone)/i', strtolower($_SERVER['HTTP_USER_AGENT']))) {
         $is_mobile=1;
        }

    if((strpos(strtolower($_SERVER['HTTP_ACCEPT']),'application/vnd.wap.xhtml+xml')>0) or ((isset($_SERVER['HTTP_X_WAP_PROFILE']) or isset($_SERVER['HTTP_PROFILE'])))) {
        $is_mobile=1;
        }

         $mobile_ua = strtolower(substr($_SERVER['HTTP_USER_AGENT'],0,4));
    $mobile_agents = array('w3c ','acs-','alav','alca','amoi','andr','audi','avan','benq','bird','blac','blaz','brew','cell','cldc','cmd-','dang','doco','eric','hipt','inno','ipaq','java','jigs','kddi','keji','leno','lg-c','lg-d','lg-g','lge-','maui','maxo','midp','mits','mmef','mobi','mot-','moto','mwbp','nec-','newt','noki','oper','palm','pana','pant','phil','play','port','prox','qwap','sage','sams','sany','sch-','sec-','send','seri','sgh-','shar','sie-','siem','smal','smar','sony','sph-','symb','t-mo','teli','tim-','tosh','tsm-','upg1','upsi','vk-v','voda','wap-','wapa','wapi','wapp','wapr','webc','winw','winw','xda','xda-');

    if(in_array($mobile_ua,$mobile_agents)) {
        $is_mobile=1;
        }

        if (isset($_SERVER['ALL_HTTP'])) {
        if (strpos(strtolower($_SERVER['ALL_HTTP']),'OperaMini')>0) {
            $is_mobile=1;
            }
        }

    if (strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'windows')>0) {
         $is_mobile=0;
        }

        return $is_mobile;
    }
    /**
     * Recursive glob()
     * From some user contribution on php.net.
     */

    /**
     * @param int $pattern
     *  the pattern passed to glob()
     * @param int $flags
     *  the flags passed to glob()
     * @param string $path
     *  the path to scan
     * @return mixed
     *  an array of files in the given path matching the pattern.
     */
    function rglob($pattern = '*', $flags = 0, $path = '') {
        $paths = glob($path . '*', GLOB_MARK | GLOB_ONLYDIR | GLOB_NOSORT);
        $files = glob($path . $pattern, $flags);
        foreach ($paths as $path) {
            $files = array_merge($files, self::rglob($pattern, $flags, $path));
        }
        return $files;
    }

    function getFirstSentence($str) {
        $fp = explode('.', $str);
        echo $fp[0] . '.';
    }

    /**
     * Returns HTML for a number selector.
     * $start = 1,$end =10, $increment = 1,$append = '', $prepend = ''
     * @param type $options
     */
    static function numberSelector($options = array()) {
        $options['step'] = isset($options['step']) ? $options['step'] : 1;
        $numbers = range($options['start'], $options['end'], $options['step']);
//        array_walk($numbers,'function(){return $prepend.$value.$append;}',);
        $variables['numberSelector'] = new OptionBox(array('optionBoxData' => array('test' => 'testval'), 'dBTableOptions' => array('className' => 'Tag_Models_Tag', 'cols' => 'title'), 'multiSelect' => 1, 'id' => "tagselector_{$variables['object']->id}", 'name' => 'tags'));
    }

    static function flashMessage($message, $type = 'valid') {
        return "<div class='{$type}Box'>{$message}</div>";
    }

    public static function printMsgBox($type, $content) {
        $type = strtolower($type);
        switch ($type) {
            case 'ok':
                $type = 'OK';
                break;
            default:
                $type = ucwords($type);
                break;
        }

        echo '<div class="msgBox'.$type.'"><span class="msgIcon"></span>'.$content.'</div>';
    }
    
    static function redirect_to($options){
        $url = $options['url'];
        $domain = 'http://'.$_SERVER['SERVER_NAME'].'/';
        echo "<script>window.location='{$domain}".str_replace($domain, '', $url)."';</script>";
//        header("Location: {$domain}{$url}");
    }

    static function debug($data) {
        echo '<code>';
        echo '<pre>';
        print_r($data);
        echo '</pre>';
        echo '</code>';
    }

    static function cleanCache($table,$id){
        $files = array_merge(
                glob(PUBLIC_FOLDER.DS.'tmp'.DS.'*preview_'.$id.'*'),
                glob(PUBLIC_FOLDER.DS.'tmp'.DS.'*'.$table.'_'.$id.'*')

        );
        foreach($files as $file){
            unset($file);
        }
    }
    static function parseClassName($className) {
        $array = explode('_', $className);
        $array[2] = str_replace('sController', '', $array[2]);
        return array($array[0], $array[0] . '_Models_' . $array[2], $array[0] . '_Controllers_' . $array[2] . 'sController', $array[2], $array[0] . '_' . $array[2] . 's');
    }

    static function includeCSS($fileName, $type = 'file') {
        $data = '';
        switch ($type) {
            case 'url':
                $data = '<link href="' . $fileName . '" rel="stylesheet" type="text/css" media="screen" />';
                break;
            default:
                if (file_exists(SITES_DIRECTORY . DS . SITE_NAME . '/public' . DS . 'css' . DS . $fileName . '.css')) {
                    $data = '<link href="' . BASE_PATH_ROOT . '/css/' . $fileName . '.css' . '" rel="stylesheet" type="text/css" media="screen" />' . "\n";
                }
                break;
        }
        return $data;
    }

    static function includeCSSFiles($fileNames, $newfile = 'generatedCSS') {
        if (Config::getConfig('ENVIRONMENT') == 'DEVELOPMENT' || !file_exists(PUBLIC_FOLDER . DS . 'css' . DS . 'generatedCSS.css')) {
            $data = '';
            foreach ($fileNames as $fileName) {
                if (file_exists(PUBLIC_FOLDER . '/css/' . $fileName . '.css')){
                    $data .= file_get_contents(BASE_PATH_ROOT . '/css/' . $fileName . '.css');
                }else if (file_exists(GLOBAL_RESOURCES .DS. 'css'.DS .$fileName . '.css')){
                    $data .= file_get_contents(GLOBAL_RESOURCES .DS. 'css'.DS . $fileName . '.css');
                }
            }
            $data = preg_replace('!/\*[^*]*\*+([^/][^*]*\*+)*/!', '', $data);
            // Remove tabs, excessive spaces and newlines
            $data = str_replace(array("\r\n", "\r", "\n", "\t", '  ', '   '), '', $data);
            $cssFile = fopen(PUBLIC_FOLDER . DS . 'css' . DS . $newfile . '.css', 'w');
            fwrite($cssFile, $data);
            fclose($cssFile);
        }
        echo self::includeCSS($newfile);
    }

    
    static function includeJSFiles($fileNames, $newfile = 'generatedJS') {
        if (Config::getConfig('ENVIRONMENT') == 'DEVELOPMENT' || !file_exists(PUBLIC_FOLDER . DS . 'js' . DS . 'generatedJS.js')) {
            $data = '';
            foreach ($fileNames as $fileName) {
                if (file_exists(PUBLIC_FOLDER . DS . 'js' . DS . $fileName . '.js')) {
                    $data .= file_get_contents(PUBLIC_FOLDER . DS . 'js' . DS . $fileName . '.js');
                } else if (file_exists(GLOBAL_RESOURCES . DS . 'js' . DS . $fileName . '.js')) {
                    $data .= file_get_contents(GLOBAL_RESOURCES . DS . 'js' . DS . $fileName . '.js');
                }
            }
            $jsFile = fopen(PUBLIC_FOLDER . DS . 'js' . DS . $newfile . '.js', 'w');
            fwrite($jsFile, $data);
            fclose($jsFile);
        }
        echo self::includeJS($newfile);
    }

    static function includeJS($fileName, $type = 'file') {
        $data = '';
        switch ($type) {
            case 'url':
                $data = "<script type='text/javascript'  src='{$fileName}'></script>";
                break;
            default:
                if (file_exists(SITES_DIRECTORY . DS . SITE_NAME.DS.'public' . DS . 'js' . DS . $fileName . '.js')) {
                    $data = '<script type="text/javascript"  src="' . BASE_PATH_ROOT . DS .  'js' . DS . $fileName . '.js"></script>' . "\n";
                }
                break;
        }
        return $data;
    }

    function printRecord($record) {
        echo '<pre>';
        print_r($record);
        echo '</pre>';
    }

    function arrayDiff($ary_1, $ary_2) {
        // compare the value of 2 array
        // get differences that in ary_1 but not in ary_2
        // get difference that in ary_2 but not in ary_1
        // return the unique difference between value of 2 array

        $diff1 = array_diff($ary_1, $ary_2);
        $diff2 = array_diff($ary_2, $ary_1);


        return array('ExtraFieldsArray1' => $diff1, 'ExtraFieldsArray2' => $diff2);
    }

    function isArrayEmpty($array) {
        $arrayEmpty = false;
        foreach ($array as $v) {
            if (empty($v)) {
                $arrayEmpty = false;
            } else {
                $arrayEmpty = true;
                break;
            }
        }
        return $arrayEmpty;
    }

    function log($message, $fileName = 'general.log') {
        $cacheLogFile = fopen(PUBLIC_FOLDER . DS . 'tmp' . DS . $fileName, 'a');
        if ($cacheLogFile) {
//        	$str = strftime('%F %T').' - '.$msg."\n";
            fwrite($cacheLogFile, $message);
            fclose($cacheLogFile);
        }
    }

    public static function webSafeString($contentSlug) {
        $contentSlug = preg_replace("`\[.*\]`U", "", $contentSlug);
        $contentSlug = preg_replace('`&(amp;)?#?[a-z0-9]+;`i', '-', $contentSlug);
        $contentSlug = htmlentities($contentSlug, ENT_COMPAT, 'utf-8');
        $contentSlug = preg_replace("`&([a-z])(acute|uml|circ|grave|ring|cedil|slash|tilde|caron|lig|quot|rsquo);`i", "\\1", $contentSlug);
        $contentSlug = strtolower(preg_replace(array("`[^a-z0-9]`i", "`[-]+`"), "-", $contentSlug));
        return $contentSlug;
    }

    public function googleTrackingCode($pageURL = '', $pageTitle = '') {
        global $page;
        $pageURL = str_replace('//', '/', '/' . (!empty($pageURL) ? $pageURL : $page->url)); #replace
        $pageTitle = !empty($pageTitle) ? $pageTitle : $page->pageTitle; #replace
        ?>
        <script>
            (function(i, s, o, g, r, a, m) {
                i['GoogleAnalyticsObject'] = r;
                i[r] = i[r] || function() {
                    (i[r].q = i[r].q || []).push(arguments)
                }, i[r].l = 1 * new Date();
                a = s.createElement(o),
                        m = s.getElementsByTagName(o)[0];
                a.async = 1;
                a.src = g;
                m.parentNode.insertBefore(a, m)
            })(window, document, 'script', '//www.google-analytics.com/analytics.js', 'ga');

            ga('create', 'UA-39763604-1', 'bollyduniya.com');
            ga('send', 'pageview', {'page': '<?php echo $pageURL; ?>', 'title': '<?php echo $pageTitle; ?>'});

            var clicky_site_ids = clicky_site_ids || [];
            clicky_site_ids.push(100608928);
            (function() {
                var s = document.createElement('script');
                s.type = 'text/javascript';
                s.async = true;
                s.src = '//static.getclicky.com/js';
                (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(s);
            })();
        </script>
        <noscript><img alt="Clicky" width="1" height="1" src="//in.getclicky.com/100608928ns.gif" /></noscript>
        <?php
    }

    
    function dropboxApiKeyandToken() {
        //BYsdzkqM1dAAAAAAAAAAB5BCg1CDOUZeKSqx07mdaj_kp6ptVEfhf1HtWrKnLTlC
        $variables = array_shift(User_Models_User::find_all(array()));
        $client = new Dropbox\Client("$variables->dropbox_token", "hr_bezoar", 'UTF-8');

        try {
            $client = new Dropbox\Client("$variables->dropbox_token", "hr_bezoar", 'UTF-8');
            // $client = $client->getAccountInfo();
            return $client;
        } catch (Exception $e) {
            return false;
        }
      
    }

    public static function  dompdf(){       
              $dompdf =  new Dompdf\Dompdf();             
        return $dompdf;
    }

    public static function printFormatedDates($options = '') {
        $startDate = new DateTime($options['startDate']);
		$endDate = !empty($options['endDate'])?new DateTime($options['endDate']):$startDate;
		$dateFormat = !empty($options['dateFormat'])?$options['dateFormat']:'F j, Y';

        if ($startDate->format('mdY') != $endDate->format('mdY')) {
            if ($startDate->format('m') != $endDate->format('m')) {
                echo $startDate->format('F j').' - '.$endDate->format('F j, Y');
            } else if ($startDate->format('d') != $endDate->format('d')) {
                echo $startDate->format('F j').' - '.$endDate->format('j, Y');
            } else {
                echo $startDate->format('F j, Y').' - '.$endDate->format('F j, Y');
            }
        } else {
            echo $startDate->format($dateFormat);
        }
        if(empty($options['noBRTag'])){
            echo '<br />';
        }
    }

    public static function countTime($hours='', $minutes='') {  // first - hours ,  second -  minutes
        
        if(empty($hours) && empty($minutes)){
            return  $error = '<label style="color:red;" class="error">Pass The Parameters Hours and Minutes</label>';
        }    
        $total_hours = is_array($hours) ? array_sum($hours) : $hours;
        $total_minutes = is_array($minutes) ? array_sum($minutes) : $minutes; 
        $addhours_minutes = floor($total_minutes / 60);
        $total_hours += $addhours_minutes;
        $minutes = ($total_minutes % 60);
        return sprintf('%02d:%02d', $total_hours, $minutes);
    }

    public static function toUpper($str) {
        return ucwords(str_replace('_', ' ', $str));
	    /*return mb_convert_case(mb_strtolower(str_replace('_', ' ', $str)), MB_CASE_TITLE, "UTF-8");*/
    }
}

/*
 * 	--------------------------------------------------------------------------------------------------------------------------
 * 	Program			: HTML Form Field Generator, PHP Class Library
 * 	Version			: 1.0.0
 * 	Files			: htmlform.inc.php, htmlform_base.inc.php, htmlform_exc.inc.php
 * 	Author			: Lasantha Samarakoon
 * 	Date released	: Monday, September 21, 2009
 * 	Email			: lasn1987@gmail.com
 * 	Licence			: http://www.gnu.org/licenses/gpl.txt
 * 	--------------------------------------------------------------------------------------------------------------------------
 *
 * 	This program is a freeware, which falls under GNU Genral Public Licence.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	You can modify this program, without any permission from the author. But be kind enough to send the updated version to the
 * 	author through the above mentioned Email address.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	Documentation:
 * 			Please refer the test.php file for hints on the usage of this class library.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	************************************* PROUD TO BE A SRI LANKAN...!!! ******************************************************
 */

/*
 * 	--------------------------------------------------------------------------------------------------------------------------
 * 	Program			: HTML Form Field Generator, PHP Class Library
 * 	Version			: 1.0.0
 * 	Files			: htmlform.inc.php, htmlform_base.inc.php, htmlform_exc.inc.php
 * 	Author			: Lasantha Samarakoon
 * 	Date released	: Monday, September 21, 2009
 * 	Email			: lasn1987@gmail.com
 * 	Licence			: http://www.gnu.org/licenses/gpl.txt
 * 	--------------------------------------------------------------------------------------------------------------------------
 *
 * 	This program is a freeware, which falls under GNU Genral Public Licence.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	You can modify this program, without any permission from the author. But be kind enough to send the updated version to the
 * 	author through the above mentioned Email address.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	Documentation:
 * 			Please refer the test.php file for hints on the usage of this class library.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	************************************* PROUD TO BE A SRI LANKAN...!!! ******************************************************
 */

// exceptions
class NullElementException extends Exception {

    function __construct() {
        parent::__construct("Element cannot be null");
    }

}

class InvalidParameterException extends Exception {

    function __construct($req) {
        parent::__construct("Invalid parameter entered. Required: $req");
    }

}

/*
 * 	--------------------------------------------------------------------------------------------------------------------------
 * 	Program			: HTML Form Field Generator, PHP Class Library
 * 	Version			: 1.0.0
 * 	Files			: htmlform.inc.php, htmlform_base.inc.php, htmlform_exc.inc.php
 * 	Author			: Lasantha Samarakoon
 * 	Date released	: Monday, September 21, 2009
 * 	Email			: lasn1987@gmail.com
 * 	Licence			: http://www.gnu.org/licenses/gpl.txt
 * 	--------------------------------------------------------------------------------------------------------------------------
 *
 * 	This program is a freeware, which falls under GNU Genral Public Licence.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	You can modify this program, without any permission from the author. But be kind enough to send the updated version to the
 * 	author through the above mentioned Email address.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	Documentation:
 * 			Please refer the test.php file for hints on the usage of this class library.
 * 	---------------------------------------------------------------------------------------------------------------------------
 * 	************************************* PROUD TO BE A SRI LANKAN...!!! ******************************************************
 */

interface IGeneratable {

// this function is used to generate html coding.
    function generate();
}

// this is the base class for all form fields except checkbox and radio
abstract class FormField {

    protected $properties = array('name' => null, 'id' => null, 'className' => null, 'multiSelect' => null, 'disabled' => false, 'text' => '', 'value' => NULL, 'rel' => NULL);

// constructor
    function __construct($options = array()) {
        foreach ($this->properties as $propertyKey => $propertyValue) {
            $this->$propertyKey = !empty($options[$propertyKey]) ? $options[$propertyKey] : $propertyValue;
        }
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
    }

    function __set($key, $val) {

        if ($key == 'disabled')
            if (!is_bool($val))
                throw new InvalidParameterException("boolean (true or false)");

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

}

// this is the base class for text, password and hidden fields
abstract class TextFieldBase extends FormField {

// constructor
    function __construct($options = array()) {
//$name = null, $id = null, $value = null, $className = null, $disabled = false
// invoke super class constructor
        parent::__construct($options);
        $this->properties['value'] = !empty($options['value']) ? $options['value'] : null;
    }

    function generate_field($type) {
        $r = "<input type=\"$type\"";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->value != null)
            $r .= " value=\"{$this->value}\"";
        if ($this->disabled == true)
            $r .= " disabled=\"disabled\"";

        $r .= " />";
        // return html code
        return $r;
    }

}

// this is the base class for checkbox and radio
abstract class CheckboxBase extends FormField {

    //constructor
    function __construct($options = array()) {
        // invoke super class constructor
        parent::__construct($options);
        $this->properties['checked'] = !empty($options['checked']) ? $options['checked'] : false;
        //        $this->checked = $checked;
    }

    function __set($key, $val) {

        if ($key == 'checked')
            if (!is_bool($val))
                throw new InvalidParameterException("boolean (true or false)");

        parent::__set($key, $val);
    }

    function generate_field($type) {

        $r = "<span>";
        $r .= "<input type=\"$type\"";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->checked == true)
            $r .= " checked=\"checked\"";
        if ($this->disabled == true)
            $r .= " disabled=\"disabled\"";
        if ($this->value != null)
            $r .= " value=\"{$this->value}\"";

        $r .= " />";
        $r .= ($this->text != null) ? ' ' . $this->text . ' ' : '';
        $r .= "</span>";
// return html code
        return $r;
    }

}

// this is the base class for all buttons
abstract class ButtonBase extends FormField {

// constructor
    function __construct($options = array()) {
// invoke super class constructor
        parent::__construct($options);

        $this->properties['value'] = !empty($options['value']) ? $options['value'] : null;
    }

    function generate_field($type) {

        $r = "<button type=\"$type\"";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->disabled == true)
            $r .= " disabled=\"disabled\"";

        $r .= ">{$this->value}</button>";
// return html code
        return $r;
    }

}

// this class is used to generate html form element
class HTMLForm implements IGeneratable {

    private $properties = array('name' => null,
        'id' => null,
        'enctype' => null,
        'action' => null,
        'method' => null,
        'className' => null,
        'ajaxifiedForm' => null,
        'keep_visible' => null,
        'keep_result' => null,
    );
    private $_elems = array();

// constructor
    function __construct($options = array()) {
//		$name = null, $id = null, $action = null, $method = null, $enctype = null, $className = null
        $this->name = !empty($options['name']) ? $options['name'] : null;
        $this->id = !empty($options['id']) ? $options['id'] : null;
        $this->className = !empty($options['className']) ? $options['className'] : null;
        $this->action = !empty($options['action']) ? $options['action'] : null;
        $this->method = !empty($options['method']) ? $options['method'] : null;
        $this->enctype = !empty($options['enctype']) ? $options['enctype'] : null;
        $this->keep_visible = !empty($options['keep_visible']) ? $options['keep_visible'] : null;
        $this->keep_result = !empty($options['keep_result']) ? $options['keep_result'] : null;
        $this->ajaxifiedForm = !empty($options['ajaxifiedForm']) ? $options['ajaxifiedForm'] : null;
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
        else
            return null;
    }

    function __set($key, $val) {

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

    function generate() {

        $r = '';
//Add title of form//
//create an empty div for form results//
        if ($this->ajaxifiedForm != null) {
            $r = "<div name='{$this->name}_form_result' id='{$this->id}_form_result' class='resultDiv' ></div>";
            $r .= "<div class='spacer10'></div>";
        }
// create form
        $r .= "<form";

        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->enctype != null)
            $r .= " enctype=\"{$this->enctype}\"";
        if ($this->action != null)
            $r .= " action=\"{$this->action}\"";
        if ($this->method != null)
            $r .= " method=\"{$this->method}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->ajaxifiedForm != null)
            $r .= " rel='ajaxifiedForm' ";
        if ($this->keep_visible != null)
            $r .= " keep_visible='1' ";
        if ($this->keep_result != null)
            $r .= " keep_result='1' ";
        $r .= ">";

        // add components
        foreach ($this->_elems as $e) {
            $r .= $e->generate();
        }

        // close form
        $r .= "</form>";

// return html code
        return $r;
    }

// this function is used to add form elements to the form
    function addElement($elem, $elname) {

// check all required parameters are not null
        if ($elem != null && $elname != null)
            $this->_elems[$elname] = $elem;
        else
            throw new NullElementException();
    }

// this function is used to remove elements from the form
    function removeElement($elname) {

// temporary array to save filtered components
        $new_elems = array();

// traverse through the component collection
        foreach ($this->_elems as $k => $v)
            if (strtolower($k) != strtolower($elname))
                $new_elems[$k] = $v; // save filtered components to the new temporary array

// set the reproduced array as the component collection
        $this->_elems = $new_elems;
    }

}

// create html text input command
class TextField extends TextFieldBase implements IGeneratable {

    function generate() {
        return parent::generate_field('text');
    }

}

// create html hidden input command
class HiddenField extends TextFieldBase implements IGeneratable {

    function generate() {
        return parent::generate_field('hidden');
    }

}

// create html password input command
class PasswordField extends TextFieldBase implements IGeneratable {

    function generate() {
        return parent::generate_field('password');
    }

}

// create html checkbox command
class CheckBox extends CheckboxBase implements IGeneratable {

    function generate() {
        return parent::generate_field('checkbox');
    }

}

// create html radio button command
class Radio extends CheckboxBase implements IGeneratable {

    function generate() {
        return parent::generate_field('radio');
    }

}

// create html textarea element
class Textarea extends FormField implements IGeneratable {

// constructor
    function __construct($options = array()) {

// invoke super class constructor
        parent::__construct($options);
        $this->properties['value'] = !empty($options['value']) ? $options['value'] : null;
    }

    function generate() {

        $r = "<textarea";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->disabled)
            $r .= " disabled=\"disabled\"";

        $r .= ">{$this->value}</textarea>";
//return html coding
        return $r;
    }

}

// create html submit button command
class SubmitButton extends ButtonBase implements IGeneratable {

    function generate() {
        return parent::generate_field('submit');
    }

}

// create html image submit button command
class ImageButton extends ButtonBase implements IGeneratable {

// constructor
    function __construct($options = array()) {
// invoke super class constructor
        parent::__construct($options);

        $this->properties['value'] = !empty($options['value']) ? $options['value'] : null;
        $this->properties['image_src'] = !empty($options['image_src']) ? $options['image_src'] : null;
    }

    function generate() {

        $r = "<input type='image' ";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->disabled == true)
            $r .= " disabled=\"disabled\"";
        if ($this->image_src != null)
            $r .= " src=\"{$this->image_src}\"";

        $r .= " />";
        // return html code
        return $r;
    }

}

// create html reset button command
class ResetButton extends ButtonBase implements IGeneratable {

    function generate() {
        return parent::generate_field('reset');
    }

}

// create html button command
class GeneralButton extends ButtonBase implements IGeneratable {

    function generate() {
        return parent::generate_field('button');
    }

}

// create html label element
class Label implements IGeneratable {

    private $properties = array('value' => null, 'id' => null, 'rel' => null, 'className' => null);

    // constructor
    function __construct($options = array()) {
        $this->value = !empty($options['value']) ? $options['value'] : null;
        $this->id = !empty($options['id']) ? $options['id'] : null;
        $this->rel = !empty($options['rel']) ? $options['rel'] : null;
        $this->className = !empty($options['className']) ? $options['className'] : null;
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
        else
            return null;
    }

    function __set($key, $val) {

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

    function generate() {

        $r = "<label";
        // check for available attributes
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->rel != null)
            $r .= " rel=\"{$this->rel}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";

        $r .= ">{$this->value}</label>";
// return html coding
        return $r;
    }

}

// create html select box command
class SelectBox extends FormField implements IGeneratable {

    private $_options = array();

// constructor
    function __construct($options = array()) {
// invoke super class constructor
        parent::__construct($options);
    }

// this function is used to add options to the select box
    function addOption($options = array()) {
//		$key, $text, $value = null, $selected = false
        $sbo = new SBOption($options);
        $this->_options[$options['key']] = $sbo;
    }

// this function is used to remove options from the select box
    function removeOption($optname) {

// temporary array to save filtered options
        $new_options = array();

// traverse through the option collection
        foreach ($this->_options as $k => $v)
            if (strtolower($k) != strtolower($optname))
                $new_options[$k] = $v;

// set the reproduced array as the option collection
        $this->_options = $new_options;
    }

    function getTableData($options = array()) {
        
    }

    function generate() {

        $r = "<select";
        // check for available attributes
        if ($this->name != null)
            $r .= " name=\"{$this->name}\"";
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";
        if ($this->disabled)
            $r .= " disabled=\"disabled\"";
        if ($this->multiSelect != null)
            $r .=" size='5' multiple='multiple' ";
        if ($this->rel != null)
            $r .=" rel='{$this->rel}' ";
        $r .= ">";

        // add options
        foreach ($this->_options as $o)
            $r .= $o->generate();

        $r .= "</select>";
// return html coding
        return $r;
    }

}

// this class is used to define select box option
class SBOption implements IGeneratable {

    private $properties = array('value' => null, 'selected' => false, 'text' => null);

// constructor
    function __construct($options = array()) {
        $this->value = (isset($options['value']) && !empty($options['value'])) ? $options['value'] : '';
        $this->text = !empty($options['text']) ? $options['text'] : null;
        $this->selected = !empty($options['selected']) ? $options['selected'] : false;
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
        else
            return null;
    }

    function __set($key, $val) {

        if ($key == 'selected')
            if (!is_bool($val))
                throw new InvalidParameterException("boolean (true or false)");

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

    function generate() {

        $r = "<option";
        // check for available attributes
        $r .= " value=\"{$this->value}\"";
        if ($this->selected)
            $r .= " selected=\"selected\"";

        $r .= ">{$this->text}</option>";
// return html coding
        return $r;
    }

}

// add some style. this adds a line break after the element and clears float.
class Spacer implements IGeneratable {

    private $properties = array('value' => null, 'id' => null, 'rel' => null, 'className' => null);

// constructor
    function __construct($options = array()) {
        $this->value = !empty($options['value']) ? $options['value'] : null;
        $this->id = !empty($options['id']) ? $options['id'] : null;
        $this->rel = !empty($options['rel']) ? $options['rel'] : null;
        $this->className = !empty($options['className']) ? $options['className'] : null;
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
        else
            return null;
    }

    function __set($key, $val) {

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

    function generate() {

        $r = "<div";
        // check for available attributes
        if ($this->id != null)
            $r .= " id=\"{$this->id}\"";
        if ($this->rel != null)
            $r .= " rel=\"{$this->rel}\"";
        if ($this->className != null)
            $r .= " class=\"{$this->className}\"";

        $r .= ">{$this->value}</div>";
// return html coding
        return $r;
    }

}

class ButtonLinkSubmit implements IGeneratable {

    private $properties = array('value' => 'Submit', 'className' => null, 'imageClass' => null, 'submitTo' => null);

// constructor
    function __construct($options = array()) {

        $this->value = !empty($options['value']) ? $options['value'] : null;
        $this->className = !empty($options['className']) ? $options['className'] : null;
        $this->imageClass = !empty($options['imageClass']) ? $options['imageClass'] : null;
        $this->submitTo = !empty($options['submitTo']) ? $options['submitTo'] : null;
    }

    function __get($key) {

        if (array_key_exists($key, $this->properties))
            return $this->properties[$key];
        else
            return null;
    }

    function __set($key, $val) {

        if ($key == 'selected')
            if (!is_bool($val))
                throw new InvalidParameterException("boolean (true or false)");

        if (array_key_exists($key, $this->properties))
            $this->properties[$key] = $val;
    }

    function generate() {

        $r = "<a class=\"{$this->className}\" href=\"javascript:void(0);\" onclick=\"$('#{$this->submitTo}').submit();\"><span class=\"buttonIcon {$this->imageClass}\">{$this->value}</span></a>";
// return html coding
        return $r;
    }

}

// create browse file button.
//Make sure form has enctype set.
// create html password input command
class FileField extends TextFieldBase implements IGeneratable {

    function generate() {
        $this->value = '';
        return parent::generate_field('file');
    }

}

class DbTableField {

    function getInputType($field) {
        $variableType = array('int', 'varchar', 'image', 'date', 'datetime');
    }

}

class OptionBox extends FormField implements IGeneratable {

    protected $properties = array(
        'name' => null,
        'id' => null,
        'className' => null,
        'disabled' => false,
        'optionBoxData' => array(),
        'dBTableOptions' => array(),
        'defaultValue' => null,
        'multiSelect' => false,
        'noneOption' => false,
        'noneOptionText' => 'None',
        'size' => 5,
    );
    private $_options = array();

// constructor
    function __construct($options = array()) {
// invoke super class constructor
        parent::__construct($options);
        if (!empty($this->properties['noneOption'])) {
            $this->_options[0] = $this->properties['noneOptionText'];
        }
#first get the options#
        if (!empty($this->properties['optionBoxData'])) {
            foreach ($this->properties['optionBoxData'] as $value => $text) {
                $this->_options[$value] = $text;
            }
        }
        if (!empty($this->properties['dBTableOptions'])) {
            if (empty($this->properties['dBTableOptions']['className']))
                throw new NullElementException();
            $orderBy = !empty($this->properties['dBTableOptions']['orderBy']) ? $this->properties['dBTableOptions']['orderBy'] :
                    $this->properties['dBTableOptions']['cols'] . ' asc ';
            $where = !empty($this->properties['dBTableOptions']['where']) ? $this->properties['dBTableOptions']['where'] : '';
            $join = !empty($this->properties['dBTableOptions']['join']) ? $this->properties['dBTableOptions']['join'] : '';
            $valueField = !empty($this->properties['dBTableOptions']['valueField']) ? $this->properties['dBTableOptions']['valueField'] : 'id';
            $limit = !empty($this->properties['dBTableOptions']['limit']) ? $this->properties['dBTableOptions']['limit'] : '';
            $optionBoxClass = new $this->properties['dBTableOptions']['className'];
            $optionBoxData = $optionBoxClass->find_all(array(
                'cols' => $this->properties['dBTableOptions']['cols'] . ', ' . $optionBoxClass->table . '.' . $valueField,
                'where' => $where, 'orderBy' => $orderBy, 'join' => $join, 'limit' => $limit));
            foreach ($optionBoxData as $item) {
                $this->_options[$item->$valueField] = $item->{$this->properties['dBTableOptions']['cols']};
            }
        }
    }

    function generate() {
        $optionBoxHTML = '';
        $optionBoxDataCount = count($this->_options);
        $selectBoxOptions = array('name' => $this->name, 'id' => $this->id, 'className' => $this->className);
        if ($optionBoxDataCount <= 0) { #checkbox/radio
            if (!($this->multiSelect)) { #radio
                foreach ($this->_options as $value => $text) {
                    $selectBoxOptions['checked'] = false;
                    if (is_array($this->defaultValue) && in_array($value, $this->defaultValue)) {
                        $selectBoxOptions['checked'] = true;
                    }
                    $selectBoxOptions['text'] = $text;
                    $selectBoxOptions['value'] = $value;
                    $item = new Radio($selectBoxOptions);
                    $optionBoxHTML .= "<div class=' {$this->className}'>";
                    $optionBoxHTML .= $item->generate();

                    $optionBoxHTML .= "</div>";
                }
            } else { #checkbox
                foreach ($this->_options as $value => $text) {
                    $selectBoxOptions['checked'] = false;
                    if (is_array($this->defaultValue) && in_array($value, $this->defaultValue)) {
                        $selectBoxOptions['checked'] = true;
                    }
                    $selectBoxOptions['text'] = $selectBoxOptions['value'] = $text;
                    $item = new CheckBox($selectBoxOptions);
                    $optionBoxHTML .= "<div class=' {$this->className}'>";
                    $optionBoxHTML .= $item->generate();
                    $optionBoxHTML .= "</div>";
                }
            }
        } else { #simple dropdown/multiselect drop down
            $selectBoxOptions['multiSelect'] = $this->multiSelect;
            $item = new SelectBox($selectBoxOptions);
            foreach ($this->_options as $value => $text) {
                $selected = false;
                if (is_array($this->defaultValue) && in_array($value, $this->defaultValue)) {
                    $selected = true;
                }
                $item->addOption(array('selected' => $selected, 'value' => $value, 'text' => $text, 'key' => $value));
            }
            $optionBoxHTML .= $item->generate();
            $optionBoxHTML .= "<script>$('#{$this->id}').chosen({width: '100%'});</script>";
        }
#ToDO : add search option/ fancy add/vremove box for multiselect when items are more than 10
        return $optionBoxHTML;
    }

}
