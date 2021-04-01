# Secured-Website
Class project for Building Secure Python Applications
<br><br>
Used the Flask web framework to create a HTML website that had a login page, register page, and password update page. User passwords were stored and hashed using the passlib library. Password complexity was also enforced (at least 12 characters in length, at least 1 uppercase character, 1 lowercase character, 1 number and 1 special character) common phrases like “password” were also not allowed. Users had to login to access the website, the failed logins would be added to a logger file with IP.
