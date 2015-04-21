<form action="{{mountpathed "recover/complete"}}" method="POST">
    <input type="hidden" name="token" value="{{.token}}" />
    <input type="password" name="password" placeholder="Password" value="" /><br />
    {{with .errs}}{{with $errlist := index . "password"}}{{range $errlist}}<span>{{.}}</span><br />{{end}}{{end}}{{end}}
    <input type="password" name="confirm_password" placeholder="Confirm Password" value="" /><br />
    {{with .errs}}{{with $errlist := index . "confirm_password"}}{{range $errlist}}<span>{{.}}</span><br />{{end}}{{end}}{{end}}
    <input type="hidden" name="{{.xsrfName}}" value="{{.xsrfToken}}" />
    <button type="submit">Recover</button><br />
    <a href="/login">Cancel</a>
</form>