package validate

import (
	"fmt"
	"userdb/entities"
)
func Validate(vali *entities.User)(string){

var msg string
if (len(vali.FirstName)+len(vali.LastName))>30{
	msg=fmt.Sprint("name is to large ")
	return msg//just an error
}
//check for valid email or not
//if {()
if len(vali.Email)>20{
	msg=fmt.Sprint("email is too long")
	return msg
}
if (len(vali.Password)<8) || (len(vali.Password)>20){
	msg=fmt.Sprint("passwor should be minimum 8 characters and maximum 20 characters")
	return msg
}//no.s special character , password strength, 1 letter should be numeric/specila/uppercase/lowercase
return "validated"
}