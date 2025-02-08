<?php

function error_handler($errno, $errstr, $errfile, $errline, $errcontext) {
    if (error_reporting() == 0) {
        $_SESSION['output'] .= $errstr . "\n";
    } else {
        die('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
        <html>
        <head>
            <title>Laudanum PHP DNS Access</title>
        </head>
        <body>
            <h1>Big mistake!</h1>
            <p>Sorry, an unexpected error occurred. Please try later.</p>
        </body>
        </html>');
    }
}

set_error_handler('error_handler');

$query = isset($_POST['query']) ? htmlspecialchars($_POST['query'], ENT_QUOTES, 'UTF-8') : '';
$type  = isset($_POST['type'])  ? htmlspecialchars($_POST['type'], ENT_QUOTES, 'UTF-8') : 'DNS_ANY';

if ($query != '') {
    if (filter_var($query, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        $query = strip_tags($query);
    } else {
        die('The query is invalid. Please enter a valid domain name.');
    }
}

?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
    <title>Laudanum PHP DNS Access</title>
    <link rel="stylesheet" href="style.css" type="text/css">
    <script type="text/javascript">
        function init() {
            document.dns.query.focus();
        }
    </script>
</head>
<body onload="init()">

<h1>DNS Query 0.1</h1>
<form name="dns" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST">
<fieldset>
    <legend>DNS Lookup:</legend>
    <p>Query: <input name="query" type="text" value="<?php echo $query; ?>">
    Type:
    <select name="type">
    <?php
    $types = array(
        "A" => DNS_A, "CNAME" => DNS_CNAME, "HINFO" => DNS_HINFO, "MX" => DNS_MX, 
        "NS" => DNS_NS, "PTR" => DNS_PTR, "SOA" => DNS_SOA, "TXT" => DNS_TXT, 
        "AAAA" => DNS_AAAA, "SRV" => DNS_SRV, "NAPTR" => DNS_NAPTR, "A6" => DNS_A6, 
        "ALL" => DNS_ALL, "ANY" => DNS_ANY
    );

    if (!in_array($type, array_keys($types))) {
        $type = "ANY";
    }

    foreach (array_keys($types) as $t) {
        echo "    <option value=\"$t\"" . (($type == $t) ? " SELECTED" : "") . ">$t</option>\n";
    }
    ?>
    </select>
    <input type="submit" value="Submit">
</fieldset>
</form>

<?php
if ($query != '') {
    try {
        $result = dns_get_record($query, $types[$type], $authns, $addtl);
        
        echo "<pre><results>";
        echo "Result = ";
        print_r($result);
        echo "Auth NS = ";
        print_r($authns);
        echo "Additional = ";
        print_r($addtl);
        echo "</results></pre>";
    } catch (Exception $e) {
        echo "error: " . $e->getMessage();
    }
}
?>

<hr>
</body>
</html>
