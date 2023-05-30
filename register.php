<?php
session_start();

require_once "config.php";

$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = $login_err = $register_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST["login"])) {
        // Login process
        if (empty(trim($_POST["username"]))) {
            $username_err = "Please enter your username.";
        } else {
            $username = trim($_POST["username"]);
        }

        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter your password.";
        } else {
            $password = trim($_POST["password"]);
        }

        if (empty($username_err) && empty($password_err)) {
            $sql = "SELECT id, username, password FROM users WHERE username = ?";

            if ($stmt = mysqli_prepare($db, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                $param_username = $username;

                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);

                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                        if (mysqli_stmt_fetch($stmt)) {
                            if (password_verify($password, $hashed_password)) {
                                session_start();
                                $_SESSION["loggedin"] = true;
                                $_SESSION["id"] = $id;
                                $_SESSION["username"] = $username;
                                header("location: welcome_git.php");
                            } else {
                                $login_err = "Invalid username or password.";
                            }
                        }
                    } else {
                        $login_err = "Invalid username or password.";
                    }
                } else {
                    echo "Oops! Something went wrong. Please try again later.";
                }

                mysqli_stmt_close($stmt);
            }
        }

        mysqli_close($db);
    } elseif (isset($_POST["register"])) {
        // Register process
        if (empty(trim($_POST["username"]))) {
            $username_err = "Please enter a username.";
        } else {
            $username = trim($_POST["username"]);
        }

        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter a password.";
        } elseif (strlen(trim($_POST["password"])) < 8) {
            $password_err = "Password must have at least 8 characters.";
        } else {
            $password = trim($_POST["password"]);
        }

        if (empty(trim($_POST["confirm_password"]))) {
            $confirm_password_err = "Please confirm the password.";
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if (empty($password_err) && ($password != $confirm_password)) {
                $confirm_password_err = "Password did not match.";
            }
        }

        if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {
            $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

            if ($stmt = mysqli_prepare($db, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
                $param_username = $username;
                $param_password = password_hash($password, PASSWORD_DEFAULT);

                if (mysqli_stmt_execute($stmt)) {
                    header("location: register.php");
                } else {
                    $register_err = "Oops! Something went wrong. Please try again later.";
                }

                mysqli_stmt_close($stmt);
            }
        }

        mysqli_close($db);
    }
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
  <title>Sign Up</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://unicons.iconscout.com/release/v2.1.9/css/unicons.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.5.0/css/bootstrap.min.css">
  <link rel="stylesheet" href="style_git.css">
</head>
<body>  
    <div class="container">
        <!-- <h2>Sign Up</h2>
        <p>Please fill in this form to create an account.</p> -->
        <div class="row full-height justify-content-center">
        <div class="col-12 text-center align-self-center py-5">
          <div class="section pb-5 pt-5 pt-sm-2 text-center">
            <h6 class="mb-0 pb-3"><span>Sokin Ngab </span><span>Daftar Duluuu </span></h6>
            <input class="checkbox" type="checkbox" id="reg-log" name="reg-log"/>
            <label for="reg-log"></label>
            <div class="card-3d-wrap mx-auto">
              <div class="card-3d-wrapper">
                <div class="card-front">
                  <div class="center-wrap">
                    <div class="section text-center">
                      <h4 class="mb-4 pb-3">Sokin Ngab</h4>
                      
                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                      <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">                     
                        <input type="text" class="form-style" name="username" value="<?php echo $username; ?>" placeholder="Username">
                        <span class="help-block"><?php echo $username_err; ?></span>
                        <i class="input-icon uil uil-at"></i>
                      </div>
                      <div class="form-group mt-2 <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                        <input type="password" class="form-style" name="password" placeholder="Password">
                        <span class="help-block"><?php echo $password_err; ?></span>
                        <i class="input-icon uil uil-lock-alt"></i>
                      </div>
                      <div class="form-group">
                        <input type="submit" name="login"  class="btn mt-4" value="Login">
                        
                      </div>
                      <p></p>
                  
                      <span class="help-block"><?php echo $login_err; ?></span>
                    </form>

                    </div>
                  </div>
                </div>
                <div class="card-back">
                  <div class="center-wrap">
                    <div class="section text-center">
                      <h4 class="mb-3 pb-3">Daftar Duluuu</h4>
                      
                      <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                        <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                
                          <input type="text" name="username" class="form-style" value="<?php echo $username; ?>" placeholder="Username" >
                          <span class="help-block"><?php echo $username_err; ?></span>
                          <i class="input-icon uil uil-at"></i>
                        </div>

                        <div class="form-group mt-2 <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                         
                          <input type="password" class="form-style" name="password"  placeholder="Password" > 
                          <span class="help-block"><?php echo $password_err; ?></span>
                          <i class="input-icon uil uil-lock-alt"></i>
                        </div>

                        <div class="form-group mt-2 <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                        
                          <input type="password" class="form-style" name="confirm_password" placeholder="Confirm Password">
                          <span class="help-block"><?php echo $confirm_password_err; ?></span>
                          <i class="input-icon uil uil-lock-alt"></i>
                        </div>
                            <p></p>
                        <div class="form-group">
                          <input type="submit" name="register" value="Register"class="btn btn-primary" value="Submit" >
                        </div>
                        <span class="help-block"><?php echo $register_err; ?></span>
                    </form>

                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
</body>
</html>

