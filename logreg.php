<?php
session_start(); // Start the session at the beginning of the script
include 'db_connect.php'; // Include the database connection file

// Function to sanitize data
function sanitizeData($data, $conn) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $conn->real_escape_string($data);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['register'])) { // Check if it's the registration form
        $username = sanitizeData($_POST['username'], $conn);
        $password = password_hash(sanitizeData($_POST['password'], $conn), PASSWORD_DEFAULT);
        $email = sanitizeData($_POST['email'], $conn);

        $sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";

        // Prepare and bind
        $stmt = $conn->prepare($sql);
        if ($stmt === false) {
            die("Error: " . $conn->error);
        }

        $stmt->bind_param("sss", $username, $password, $email);

        if ($stmt->execute()) {
            echo "New record created successfully";
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    }

    if (isset($_POST['login'])) { // Check if it's the login form
        $username = sanitizeData($_POST['username'], $conn);
        $password = sanitizeData($_POST['password'], $conn);

        $sql = "SELECT id, username, password FROM users WHERE username = ?";

        // Prepare and bind
        $stmt = $conn->prepare($sql);
        if ($stmt === false) {
            die("Error: " . $conn->error);
        }

        $stmt->bind_param("s", $username);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();

                if (password_verify($password, $user['password'])) {
                    // Password is correct, so start a new session
                    $_SESSION['loggedin'] = true;
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['id'] = $user['id'];

                    echo "Logged in successfully";
                } else {
                    echo "Invalid username or password";
                }
            } else {
                echo "Invalid username or password";
            }
        } else {
            echo "Error: " . $stmt->error;
        }
        
        $stmt->close();
    }
}

$conn->close();
?>
