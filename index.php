<?php
/**
 * Power BI Dashboard Access Gate
 * --------------------------------
 * This file handles user authentication, session management, and secure
 * internal audit logging before displaying a restricted Power BI dashboard.
 * All sensitive logic (credentials, logging) is processed server-side (PHP).
 */

// Start the session at the very beginning of the file.
session_start();

// --- CONFIGURATION ---
const CORRECT_EMAIL = "ygemii@gmail.com";
const CORRECT_PASSWORD = "Test123456";
// Log file path points one directory UP (outside htdocs) for security.
const LOG_FILE = '../private_access_log.txt'; 

// Power BI Iframe URL 
const DASHBOARD_URL = "https://app.powerbi.com/view?r=eyJrIjoiYjRjNmZhZDgtYjY3Ni00OWI4LTg2ZjMtZTIyNzU0OTFiYzVkIiwidCI6ImRjYmJhNzgwLTM1M2UtNGU4OC00OWY5LTZmNGZmYTdjODM4YSIsImMiOjl9";

// --- STATE AND INITIALIZATION ---
$is_authenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
$error_message = '';


// --- FUNCTIONS ---

/**
 * Creates a successful login audit log entry outside the web root.
 * @param string $email The email of the logged-in user.
 * @return bool True on success, False on failure.
 */
function log_successful_access(string $email): bool
{
    $log_entry = date('Y-m-d H:i:s') . 
                 " | SUCCESS | USER: " . $email . 
                 " | IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "\n";
    
    // Use FILE_APPEND to add to the end, and LOCK_EX to prevent concurrent write issues.
    return (bool)file_put_contents(LOG_FILE, $log_entry, FILE_APPEND | LOCK_EX);
}

/**
 * Handles user logout by destroying the session and redirecting.
 */
function handle_logout(): void
{
    $_SESSION = array();
    session_destroy();
    header("Location: index.php");
    exit;
}

// --- HANDLE LOGOUT REQUEST ---
if (($_POST['action'] ?? '') === 'logout') {
    handle_logout();
}

// --- HANDLE LOGIN SUBMISSION ---
if (!$is_authenticated && $_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === CORRECT_EMAIL && $password === CORRECT_PASSWORD) {
        // 1. Authentication Success
        $_SESSION['authenticated'] = true;

        // 2. Audit Logging (Still runs silently)
        log_successful_access($email);

        // 3. Redirect (Post-Redirect-Get pattern for security)
        // Note: The notification status setting logic was removed here.
        header("Location: index.php");
        exit;

    } else {
        // Authentication Failure
        $error_message = 'Invalid email or password. Please check your credentials.';
    }
}

// --- HTML OUTPUT ---
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Dashboard Access</title>
    <!-- Load Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom styles for a cleaner UI, ensuring full height and centering */
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            /* Adjust body layout when authenticated */
            <?php if ($is_authenticated): ?>
            display: block;
            padding: 0; /* Remove padding when dashboard is full screen */
            <?php endif; ?>
        }

        /* Ensure the dashboard container takes up space when visible */
        #dashboard-container {
            width: 100%;
            height: 100vh; /* Full height when authenticated */
            max-width: none;
            margin: auto;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        #dashboard-container iframe {
            width: 100%;
            height: 100%;
            border-radius: 0; /* No rounding for full screen */
        }
    </style>
</head>
<body>

    <?php if (!$is_authenticated): ?>
    <!-- ====================================
         LOGIN FORM (Visible if not authenticated)
         ==================================== -->
    <div id="login-card" class="bg-white p-8 rounded-xl shadow-2xl w-full max-w-md">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">Risk Dashboard Access</h1>
        <p class="text-gray-600 mb-8 text-center">Authentication required to view sensitive risk data.</p>

        <form method="POST" action="index.php">
            <div class="mb-5">
                <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
                <input type="email" id="email" name="email" required
                       class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                       placeholder="Enter your email"
                       value="<?= htmlspecialchars($email ?? '') ?>">
            </div>

            <div class="mb-6">
                <label for="password" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                <input type="password" id="password" name="password" required
                       class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                       placeholder="Enter your password">
            </div>

            <!-- Error Message Display -->
            <?php if (!empty($error_message)): ?>
            <div id="error-message" class="text-sm text-red-600 mb-4 font-medium p-2 bg-red-50 rounded-lg border border-red-200">
                <?= htmlspecialchars($error_message); ?>
            </div>
            <?php endif; ?>

            <button type="submit"
                    class="w-full bg-blue-600 text-white py-2.5 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300 font-semibold transition duration-200 ease-in-out shadow-md hover:shadow-lg">
                Sign In
            </button>
        </form>
    </div>

    <?php else: // Display Dashboard if authenticated ?>
    
    <!-- ====================================
         DASHBOARD VIEW (Visible if authenticated)
         ==================================== -->
    <!-- The notification banner display block was removed here. -->

    <!-- Dashboard Container -->
    <div id="dashboard-container" class="relative">
        
        <!-- Logout Button (Fixed Position for Visibility) -->
        <form method="POST" action="index.php" class="absolute top-4 right-4 z-10">
            <input type="hidden" name="action" value="logout">
            <button type="submit" class="bg-gray-700 text-white text-sm py-1 px-3 rounded-lg hover:bg-gray-800 transition duration-200 ease-in-out shadow-lg">
                Logout
            </button>
        </form>

        <!-- The Power BI Iframe -->
        <iframe title="Risk Dashboard - Opera"
                src="<?= htmlspecialchars(DASHBOARD_URL); ?>"
                frameborder="0" allowFullScreen="true"
                class="shadow-xl">
        </iframe>
    </div>

    <?php endif; ?>

</body>
</html>