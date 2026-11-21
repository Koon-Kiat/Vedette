"""Error pages, and the redirect to the login page when a session is missing."""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from starlette.exceptions import HTTPException

from vedette.web.auth import SESSION_COOKIE
from vedette.web.dashboard import ERROR_TITLES, FINDING_PATH, LoginRequired, dashboard_of, is_htmx


def install(app: FastAPI) -> None:
    """Register the error handlers on ``app``."""

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired) -> Response:
        if is_htmx(request):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def error_page(request: Request, exc: HTTPException) -> Response:
        dashboard = dashboard_of(request)
        message = (
            exc.detail if exc.status_code in (400, 403, 422, 429) else "That page does not exist."
        )
        heading = ERROR_TITLES.get(exc.status_code, "Something went wrong")
        if exc.status_code == 405:
            message = "That is not allowed here."
        elif exc.status_code == 404 and (found := FINDING_PATH.fullmatch(request.url.path)):
            heading = f"Finding {int(found[1]):04d} not found"
            message = (
                f"There is no finding {int(found[1]):04d}. Findings are deleted once they are "
                "older than the retention period, so a link from an old digest or alert "
                "can outlive its finding."
            )
        values: dict[str, Any] = {
            "status": exc.status_code,
            "code": exc.status_code,
            "message": message,
            "heading": heading,
            "title": heading,
        }
        # A logged-in owner keeps the menu, so the error is not a dead end.
        session = dashboard.sessions.get(request.cookies.get(SESSION_COOKIE))
        if session is not None and not is_htmx(request):
            return await dashboard.page("error.html", request, csrf=session.csrf, **values)
        return dashboard.render("error.html", **values)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> Response:
        return dashboard_of(request).render(
            "error.html",
            status=422,
            code=422,
            message="That request was not valid.",
            heading=ERROR_TITLES[422],
            title=ERROR_TITLES[422],
        )
