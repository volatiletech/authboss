<form action="{{mountpathed "consent"}}" method="POST">
    {{with .error}}{{.}}<br />{{end}}
	{{with .csrf_token}}<input type="hidden" name="csrf_token" value="{{.}}" />{{end}}
    {{with .challenge}}<input type="hidden" name="challenge" value="{{.}}" />{{end}}
    {{with .requested_audience}}
    {{range .}}<input type="hidden" value="{{.}}" name="requested_audience"> {{end}}{{end}}

    {{with .client}} {{if .name}} {{.name}} {{else}} {{.id}} {{end}} wants to access resources on your behalf with the following scopes: <br>{{end}}

    {{with .requested_scope}}
        {{range .}}
            {{.}}:  <input type="checkbox" value="{{.}}" name="grant_scope"><br>
        {{end}}
    {{end}}

    {{with .client}}
    {{with .logo_uri}}<img src="{{.}}">{{end}}
    {{with .client_uri}}<a href="{{.}}">Link</a>{{end}}
    {{with .policy_uri}}<a href="{{.}}">Policy</a>{{end}}
    {{with .tos_uri}}<a href="{{.}}">Terms Of Service</a>{{end}}
    {{end -}}

    {{with .modules}}{{with .remember}}<input type="checkbox" name="rm" value="true"> Remember Me</input><br />{{end}}{{end -}}

    <button type="submit" name="is_allowed" value="true">Allow Access</button>
    <button type="submit" name ="is_allowed" value="false">Deny Access</button>
</form>