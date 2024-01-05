# MystAuth
Easily add passkey authentication to your web app with [Myst Auth](https://mystauth.com).

Read our docs at <https://mystauth.com/docs>!

Myst Auth's source code is provided here under the [PolyForm Perimeter License](https://polyformproject.org/licenses/perimeter/1.0.1) which allows use for purposes which do not 'compete' (read license for more details) with this software. The main goal of making this code source available is to enable audits and contributions to help improve the security and functionality of Myst Auth. The `dash` app is also provided as an example app implementing Myst Auth.

Myst Auth is built using the Django Framework. The `myst` folder contains the project files, including `settings.py`. The `mystauth` folder contains the app files for the Myst Auth login portal, API, and docs. The `dash` folder contains the app files for the Myst Auth API account dashboard.

The Myst Auth documentation page was made using the [API Documentation Template made by Florian Nicolas](https://github.com/ticlekiwi/API-Documentation-HTML-Template) under the [MIT License](https://github.com/floriannicolas/API-Documentation-HTML-Template/blob/master/LICENSE):

```
MIT License

Copyright (c) 2016 Florian Nicolas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

For parts of the passkey registration and authentication process, Myst Auth uses the [`py_webauthn` package made by Cisco's Duo Labs](https://github.com/duo-labs/py_webauthn) under the [BSD 3-Clause License](https://github.com/duo-labs/py_webauthn/blob/master/LICENSE):

```
Copyright (c) 2017-2021 Duo Security, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

Background images in Myst Auth Links are from [Unsplash](https://unsplash.com) under the [Unsplash License](https://unsplash.com/license) with artist attributions listed in the [relevant section of our docs](https://mystauth.com/docs/#auth-link).
