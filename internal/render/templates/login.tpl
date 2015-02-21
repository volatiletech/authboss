<form action="/login" method="POST">
    {{if .error}}{{.error}}<br />{{end}}
    <input type="text" class="form-control" name="username" placeholder="Username" value="{{.username}}">
    <input  type="password" class="form-control" name="password" placeholder="Password">
    <input type="hidden" name="{{.xsrfName}}" value="{{.xsrfToken}}" />
    {{if .showRemember}}<input type="checkbox" name="rm" value="true"> Remember Me{{end}}
    <br />
    <button type="submit">Login</button>
    {{if .showRecover}}<a href="/recover">Recover Account</a>{{end}}
</form>