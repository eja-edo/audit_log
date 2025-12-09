UPDATE admin_users 
SET hashed_password = '$2b$12$1bA9xQ4y4DMDfLs8MC7v6OMimbbOOJuxMGO3Mjesgf3ymLbeVzj56' 
WHERE username = 'admin';

SELECT username, hashed_password FROM admin_users;
