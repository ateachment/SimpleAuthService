# SimpleAuthService
<p>Development of a simple token-based web service with Flask for teaching purposes</p>

<p>The service does <b>not yet have a database backend</b> at this stage of development.</p>

Includes:
<ul>
<li>simple UI</li>
<li>pytest file</li>
<li>OpenAPI description file</li>
</ul>

# SimpleAuthService
<p>Development of a Simple Web Token (SWT) -based web service with Flask for teaching purposes</p>

Supports login with 
<ul>
<li>User name and password</li>
</ul>

Includes:
<ul>
<li>authentification web service</li>
<li>pytest file</li>
<li>OpenAPI description file</li>
<li>MySql init file</li>
</ul>

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install requirements.

```bash
pip install -r requirements.txt
```

## Program start

```bash
python simpleAuthService.py
```

Open file:///&lt;your path to&gt;index.html directly with the browser.

## Testing

Start the test program with 
```bash
pytest testSimpleAuthService.py
```
and/or <br>
open <i>openapi.yaml</i> in https://editor.swagger.io/ and test the web service with the Swagger editor.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
