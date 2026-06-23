

export function parse_recidivism(recividism_string) {
	if(recividism_string === undefined || recividism_string === null) {
		return null;
	}
	let recidivism_obj = {
		version: recividism_string.split(":")[0],
		severity: recividism_string.split(":")[1]
	}
  return recidivism_obj;
}
