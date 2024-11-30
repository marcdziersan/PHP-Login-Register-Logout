Dieses Repository erklärt, wie man ein sicheres Login-System mit PHP und MySQL implementieren könnte.

### 1. **Datenbankstruktur**
   - Eine Tabelle `users` wird mit den Feldern `id`, `email`, `passwort`, `vorname`, `nachname`, `created_at` und `updated_at` erstellt.
   - Passwörter werden mit `password_hash()` sicher verschlüsselt und in der Datenbank gespeichert.

### 2. **Registrierung**
   - In `registrieren.php` wird ein Formular zur Nutzerregistrierung bereitgestellt.
   - Das Formular überprüft die E-Mail-Adresse auf Gültigkeit und ob die Passwörter übereinstimmen.
   - Bei erfolgreicher Registrierung wird das Passwort gehasht und der Nutzer in die Datenbank eingefügt.

### 3. **Login**
   - In `login.php` wird das Login-Formular erstellt, das die E-Mail-Adresse und das Passwort des Nutzers prüft.
   - Wenn die Daten korrekt sind, wird die Session mit der Benutzer-ID gestartet.
   - Die Funktion `password_verify()` prüft, ob das eingegebene Passwort mit dem gespeicherten gehashten Passwort übereinstimmt.

### 4. **Geschützter Bereich**
   - In `geheim.php` wird geprüft, ob die Session-Variable `userid` gesetzt ist. Wenn nicht, wird der Nutzer aufgefordert, sich einzuloggen.

### 5. **Logout**
   - In `logout.php` wird die Session zerstört, um den Nutzer abzumelden.

Die grundlegenden Schritte umfassen also:
- Registrierung (mit Passwort-Hashing)
- Login (mit Passwort-Verifikation)
- Geschützten Bereich (nur zugänglich für eingeloggte Nutzer)
- Logout (Session beenden)

Hier sind die entsprechenden Quelltexte für das Login-, Registrierung-, geschützte Bereich- und Logout-System:

### 1. **Datenbankstruktur (MySQL)**
   Erstelle eine `users` Tabelle mit folgendem SQL-Code:
   ```sql
   CREATE TABLE `users` (
     `id` INT NOT NULL AUTO_INCREMENT,
     `email` VARCHAR(255) NOT NULL,
     `passwort` VARCHAR(255) NOT NULL,
     `vorname` VARCHAR(255) NOT NULL DEFAULT '',
     `nachname` VARCHAR(255) NOT NULL DEFAULT '',
     `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     `updated_at` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     PRIMARY KEY (`id`), UNIQUE (`email`)
   ) ENGINE = InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
   ```

### 2. **Registrierung (registrieren.php)**
```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'root', '');

$showFormular = true;

if(isset($_GET['register'])) {
    $error = false;
    $email = $_POST['email'];
    $passwort = $_POST['passwort'];
    $passwort2 = $_POST['passwort2'];

    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo 'Bitte eine gültige E-Mail-Adresse eingeben<br>';
        $error = true;
    }
    if(strlen($passwort) == 0) {
        echo 'Bitte ein Passwort angeben<br>';
        $error = true;
    }
    if($passwort != $passwort2) {
        echo 'Die Passwörter müssen übereinstimmen<br>';
        $error = true;
    }

    // Überprüfe, ob E-Mail bereits existiert
    if(!$error) {
        $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
        $statement->execute(array('email' => $email));
        $user = $statement->fetch();

        if($user !== false) {
            echo 'Diese E-Mail-Adresse ist bereits vergeben<br>';
            $error = true;
        }
    }

    // Keine Fehler, registriere den Nutzer
    if(!$error) {
        $passwort_hash = password_hash($passwort, PASSWORD_DEFAULT);

        $statement = $pdo->prepare("INSERT INTO users (email, passwort) VALUES (:email, :passwort)");
        $result = $statement->execute(array('email' => $email, 'passwort' => $passwort_hash));

        if($result) {
            echo 'Du wurdest erfolgreich registriert. <a href="login.php">Zum Login</a>';
            $showFormular = false;
        } else {
            echo 'Beim Abspeichern ist ein Fehler aufgetreten<br>';
        }
    }
}

if($showFormular) {
?>
    <form action="?register=1" method="post">
        E-Mail:<br>
        <input type="email" size="40" maxlength="250" name="email"><br><br>

        Dein Passwort:<br>
        <input type="password" size="40" maxlength="250" name="passwort"><br>

        Passwort wiederholen:<br>
        <input type="password" size="40" maxlength="250" name="passwort2"><br><br>

        <input type="submit" value="Abschicken">
    </form>
<?php } ?>
```

### 3. **Login (login.php)**
```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'root', '');

if(isset($_GET['login'])) {
    $email = $_POST['email'];
    $passwort = $_POST['passwort'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $statement->execute(array('email' => $email));
    $user = $statement->fetch();

    // Überprüfe das Passwort
    if ($user !== false && password_verify($passwort, $user['passwort'])) {
        $_SESSION['userid'] = $user['id'];
        die('Login erfolgreich. Weiter zu <a href="geheim.php">internen Bereich</a>');
    } else {
        $errorMessage = "E-Mail oder Passwort war ungültig<br>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>

<?php if(isset($errorMessage)) { echo $errorMessage; } ?>

<form action="?login=1" method="post">
    E-Mail:<br>
    <input type="email" size="40" maxlength="250" name="email"><br><br>

    Dein Passwort:<br>
    <input type="password" size="40" maxlength="250" name="passwort"><br>

    <input type="submit" value="Abschicken">
</form>
</body>
</html>
```

### 4. **Geschützter Bereich (geheim.php)**
```php
<?php
session_start();
if(!isset($_SESSION['userid'])) {
    die('Bitte zuerst <a href="login.php">einloggen</a>');
}

$userid = $_SESSION['userid'];
echo "Hallo User: ".$userid;
?>
```

### 5. **Logout (logout.php)**
```php
<?php
session_start();
session_destroy();

echo "Logout erfolgreich";
?>
```
