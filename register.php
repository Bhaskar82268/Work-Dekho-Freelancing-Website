<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include DB connection
include("includes/db.php");

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['register'])) {

    // Get form data
    $name = isset($_POST["name"]) ? trim($_POST["name"]) : '';
    $email = isset($_POST["email"]) ? trim($_POST["email"]) : '';
    $password = isset($_POST["password"]) ? trim($_POST["password"]) : '';

    // Validate fields
    if (!empty($name) && !empty($email) && !empty($password)) {

        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        // Prepare SQL
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $hashed_password);

        // Execute query
        if ($stmt->execute()) {
            // Redirect to index.html after successful registration
            header("Location: index.html");
            exit(); // Important to stop script execution
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    } else {
        echo "All fields are required!";
    }
}
?>