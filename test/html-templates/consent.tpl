<form action="{{mountpathed "consent"}}" method="POST">
    {{with .error}}{{.}}<br />{{end}}
	{{with .csrf_token}}<input type="hidden" name="csrf_token" value="{{.}}" />{{end}}
    {{with .challenge}}<input type="hidden" name="challenge" value="{{.}}" />{{end}}
    {{with .client}} {{.client_name }} {{.client_id}}  wants access resources on your behalf and to:{{end}}
    {{with .requested_scope}} {{end}}

    {{with .client}}
    {{with .policy_uri}}<a href="{{.}}">Policy</a>{{end}}
    {{with .tos_uri}}<a href="{{.}}">Terms Of Service</a>{{end}}
    {{end -}}
    {{with .modules}}{{with .remember}}<input type="checkbox" name="rm" value="true"> Remember Me</input><br />{{end}}{{end -}}

    <button type="submit" value="allow">Allow Access</button>
    <button type="submit" value="deny">Deny Access</button>
</form>