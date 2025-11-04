from flask_dance.contrib.google import make_google_blueprint
from flask_dance.contrib.github import make_github_blueprint

# Define the Google blueprint
google_bp = make_google_blueprint(
    # UPDATED: Use the modern, explicit OIDC scopes to silence the warning
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="home"
)

# Define the GitHub blueprint (no change needed here)
github_bp = make_github_blueprint(
    redirect_to="home"
)
