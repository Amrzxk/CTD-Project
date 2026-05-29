"""Repository layer.

Each module exposes thin async functions taking ``session: AsyncSession``
as the first arg. Routes obtain a session via FastAPI's
``Depends(get_session)``. The repositories are deliberately function-style
(no classes) — easier to import, easier to test, no implicit state.
"""
