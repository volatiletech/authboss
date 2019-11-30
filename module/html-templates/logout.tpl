<form action="{{mountpathed "logout"}}" method="POST">
    {{with .error}}{{.}}<br />{{end}}
	{{with .csrf_token}}<input type="hidden" name="csrf_token" value="{{.}}" />{{end}}
	{{with .redir}}<input type="hidden" name="redir" value="{{.}}" />{{end}}
    {{with .challenge}}<input type="hidden" name="challenge" value="{{.}}" />{{end}}
    Do you wish to logout?
    <button type="submit" name="shouldLogout" value="true">Yes</button>
    <button type="submit" name="shouldLogout" value="false">No</button>
</form>