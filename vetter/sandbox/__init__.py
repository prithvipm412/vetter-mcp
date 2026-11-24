"""Lite, Docker-free sandbox for dynamically exercising a demo MCP server.

Builds a throwaway fake $HOME seeded with canary secrets, launches the
server as a subprocess inside it with a Python audit-hook watching file/
network/subprocess activity and a local non-forwarding HTTP proxy standing
in for the real network, calls each advertised tool once, and reports what
actually happened.
"""
