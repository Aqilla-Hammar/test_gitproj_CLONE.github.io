<?php

    try{
        $dsn = "dbname=id20815792_destruction527; host=localhost";
        $user = "id20815792_aqillahammarr";
        $pswd = "@Anakmetal123";

        $conn = new PDO($dsn, $user, $pswd)

        $conn->query("id20815792_destruction527");
    }
    catch(PDOException $e){
        die("Error Connecting: ". $e->getMessage());
    }
?>