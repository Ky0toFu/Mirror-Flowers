<?php
// 示例：包含多种安全漏洞的PHP文件
// 警告：此代码仅用于教育目的，不要在生产环境中使用

// 漏洞1：SQL注入漏洞
function getUserData($id) {
    $conn = new mysqli("localhost", "root", "password", "myDB");
    
    // 直接拼接用户输入到SQL查询中
    $query = "SELECT * FROM users WHERE id = " . $id;
    $result = $conn->query($query);
    
    return $result->fetch_assoc();
}

// 漏洞2：跨站脚本(XSS)漏洞
function displayUserInput($input) {
    // 未对用户输入进行任何过滤或转义
    echo "您的输入是: " . $input;
}

// 漏洞3：文件包含漏洞
function includeFile($filename) {
    // 直接包含用户提供的文件名
    include($filename);
}

// 漏洞4：命令注入漏洞
function pingHost($host) {
    // 直接执行用户提供的输入作为系统命令
    system("ping -c 4 " . $host);
}

// 漏洞5：不安全的文件上传
function handleFileUpload($file) {
    // 未验证文件类型或内容
    $uploadDir = "/var/www/uploads/";
    move_uploaded_file($file['tmp_name'], $uploadDir . $file['name']);
}

// 漏洞6：会话固定攻击
session_start();
if (!isset($_SESSION['user_id'])) {
    // 使用容易预测的会话ID
    $_SESSION['user_id'] = mt_rand(1, 1000);
}

// 漏洞7：密码哈希使用弱算法
function hashPassword($password) {
    // 使用不安全的MD5哈希
    return md5($password);
}

// 漏洞8：不安全的反序列化
function unserializeData($data) {
    // 直接反序列化用户提供的数据
    return unserialize($data);
}

// 漏洞9：HTTP参数污染
function getParameter($param) {
    // 未验证参数来源
    return $_REQUEST[$param];
}

// 漏洞10：不安全的直接对象引用
function getUserProfile($userId) {
    // 未检查当前用户是否有权访问该用户ID的数据
    $conn = new mysqli("localhost", "root", "password", "myDB");
    $query = "SELECT * FROM profiles WHERE user_id = " . $userId;
    $result = $conn->query($query);
    
    return $result->fetch_assoc();
}

// 处理用户请求
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // 从URL参数获取数据并直接使用
    $userId = $_GET['user_id'];
    $userData = getUserData($userId);
    
    $userInput = $_GET['input'];
    displayUserInput($userInput);
    
    $fileToInclude = $_GET['include'];
    if ($fileToInclude) {
        includeFile($fileToInclude);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'];
    pingHost($host);
    
    if (isset($_FILES['file'])) {
        handleFileUpload($_FILES['file']);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>不安全的PHP示例</title>
</head>
<body>
    <h1>包含安全漏洞的PHP示例</h1>
    
    <form method="GET">
        <input type="text" name="user_id" placeholder="用户ID">
        <input type="text" name="input" placeholder="输入文本">
        <input type="text" name="include" placeholder="包含文件">
        <input type="submit" value="提交">
    </form>
    
    <form method="POST" enctype="multipart/form-data">
        <input type="text" name="host" placeholder="要ping的主机">
        <input type="file" name="file">
        <input type="submit" value="提交">
    </form>
</body>
</html>