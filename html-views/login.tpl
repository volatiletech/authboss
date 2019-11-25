<form action="{{mountpathed "login"}}" method="POST">
    {{with .error}}{{.}}<br />{{end}}
    <input type="text" class="form-control" name="email" placeholder="E-mail" value="{{.primaryIDValue}}"><br />
    <input type="password" class="form-control" name="password" placeholder="Password"><br />
	{{with .csrf_token}}<input type="hidden" name="csrf_token" value="{{.}}" />{{end}}
    {{with .modules}}{{with .remember}}<input type="checkbox" name="rm" value="true"> Remember Me</input><br />{{end}}{{end -}}
	{{with .redir}}<input type="hidden" name="redir" value="{{.}}" />{{end}}
    {{with .challenge}}<input type="hidden" name="challenge" value="{{.}}" />{{end}}
    <button type="submit">Login</button>
    {{with .modules}}{{with .recover}}<br /><a href="{{mountpathed "recover"}}">Recover Account</a>{{end}}{{end -}}
    {{with .modules}}{{with .register}}<br /><a href="{{mountpathed "register"}}">Register Account</a>{{end}}{{end -}}
</form>