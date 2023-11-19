$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username AND password = :password');
$stmt->bindParam(':username', $username);
$stmt->bindParam(':password', $password);
$stmt->execute();

$hashed_password = password_hash($password, PASSWORD_DEFAULT);

if (password_verify($input_password, $stored_hashed_password)) {
    // Kata sandi benar
} else {
    // Kata sandi salah
}

session_start();

if (isset($_SESSION['login_attempts']) && $_SESSION['login_attempts'] > 3) {
    // Blokir akses setelah 3 percobaan
    die('Too many login attempts. Please try again later.');
}

session_start();

$token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $token;

<input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
