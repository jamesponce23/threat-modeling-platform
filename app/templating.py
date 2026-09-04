"""Shared Jinja2 environment.

Lives here rather than in `app/templates/` because that directory is a Python
package, and a module named `app.templates` would shadow it.
"""

from __future__ import annotations

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")
