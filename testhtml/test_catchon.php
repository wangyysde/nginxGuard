<html>
<head>
<title> test for catch on </title>
</head>
<body>
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXaaaaaaa<br>
<form action="./test_catchon.php" target="_blank" name="testcatchon" method="post">
name: <input name="name" size="20" id="name"><br>
sex: <input name="sex" size=20" id="sex"><br>
<input type="submit">
</form>
<?php 
if(isset($_POST["name"])){
echo $_POST["name"]; 
echo $_POST["sex"]; 
echo "111111111X111111";
}
?>
</body>
</html>
