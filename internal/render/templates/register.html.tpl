<form action="register" method="post">
	<label for="{{.primaryID}}">{{.primaryID}}:</label>
	<input name={{.primaryID}} type="text" value="{{if .primaryIDValue}}{{.primaryIDValue}}{{end}}" placeholder="{{.primaryID}}" /><br />
	{{$pid := .primaryID}}{{with .errs}}{{with $errlist := index . $pid}}{{range $errlist}}<span>{{.}}</span><br />{{end}}{{end}}{{end}}
	<label for="password">Password:</label>
	<input name="password" type="password" placeholder="Password" /><br />
	{{with .errs}}{{range .password}}<span>{{.}}</span><br />{{end}}{{end}}
	<label for="confirm_password">Confirm Password:</label>
	<input name="confirm_password" type="password" placeholder="Confirm Password" /><br />
	{{with .errs}}{{range .confirm_password}}<span>{{.}}</span><br />{{end}}{{end}}
	<input type="submit" value="Login"><br />
	<a href="/">Cancel</a>

	<input type="hidden" name="{{.xsrfName}}" value="{{.xsrfToken}}" />
</form>