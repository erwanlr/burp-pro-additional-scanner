Latest Stable Version:
======================

Check the .jar in the build/stable directory

Features:

- Passive Scanning
  - ASP.NET Version detection
  - Potential XSS via URL parameters (only checked with params value >= 3 chars)
- Active Scanning
  - /

Manual Compilation:
=================== 

Put the burpsuite_pro.jar into the lib dir

Run ant build

Start BurpSuite Pro and add the build/additional-scanner-j1.X.jar in the extender tab
