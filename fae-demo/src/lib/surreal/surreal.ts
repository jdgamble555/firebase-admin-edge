import { getRequestEvent } from "$app/server";
import {
    PRIVATE_SURREAL_DATABASE,
    PRIVATE_SURREAL_NAMESPACE,
    PRIVATE_SURREAL_PASSWORD,
    PRIVATE_SURREAL_URL,
    PRIVATE_SURREAL_USERNAME
} from "$env/static/private";

const url = PRIVATE_SURREAL_URL;
const ns = PRIVATE_SURREAL_NAMESPACE;
const db = PRIVATE_SURREAL_DATABASE;
const username = PRIVATE_SURREAL_USERNAME;
const password = PRIVATE_SURREAL_PASSWORD;

// Base64 encode credentials for Basic Auth
const credentials = btoa(`${username}:${password}`);

export async function surrealQuery(
    query: string,
    vars?: Record<string, unknown> // optional variables
) {
    const { fetch } = getRequestEvent();

    const res = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic " + credentials,
            "Surreal-NS": ns,
            "Surreal-DB": db
        },
        body: JSON.stringify({
            query,
            vars
        })
    });

    if (!res.ok) {
        return {
            data: null,
            error: `Error ${res.status}: ${await res.text()}`
        };
    }

    return {
        data: await res.json(),
        error: null
    };
}


