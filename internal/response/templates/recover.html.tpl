<form action="{{mountpathed "recover"}}" method="POST">
    <input type="text" name="{{.primaryID}}" placeholder="{{title .primaryID}}" value="{{.primaryIDValue}}" /><br />
    {{$pid := .primaryID}}{{with .errs}}{{with $errlist := index . $pid}}{{range $errlist}}<span>{{.}}</span><br />{{end}}{{end}}{{end}}
    <input type="text" name="confirm_{{.primaryID}}" placeholder="Confirm {{title .primaryID}}" value="{{.confirmPrimaryIDValue}}" /><br />
    {{$cpid := .primaryID | printf "confirm_%s"}}{{with .errs}}{{with $errlist := index . $cpid}}{{range $errlist}}<span>{{.}}</span><br />{{end}}{{end}}{{end}}
    <input type="hidden" name="{{.xsrfName}}" value="{{.xsrfToken}}" />
    <button type="submit">Recover</button><br />
    <a href="/login">Cancel</a>
</form>