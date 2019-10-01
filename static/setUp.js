function validateForm() {
  console.log("i'm hereee")
  let client_secret = document.forms["information_form"]["client_secret"].value;
  let client_id = document.forms["information_form"]["client_id"].value;
  let primo_url = document.forms["information_form"]["primo_url"].value;
  let primo_key = document.forms["information_form"]["primo_key"].value;
  if (client_secret == "") {
    alert("Client secret must be filled out");
    return false;
  }
  if (client_id == "") {
    alert("Client ID must be filled out");
    return false;
  }
  if (primo_url == "") {
    alert("Primo Gateway must be filled out");
    return false;
  }
  if (primo_key == "") {
    alert("Primo Key must be filled out");
    return false;
  }
}