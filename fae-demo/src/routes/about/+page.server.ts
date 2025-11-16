import { error, redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { surrealQuery } from "$lib/surreal/surreal";


export const load = (async ({ locals: { authServer }, url }) => {

    const { data: user } = await authServer.getUser();

    if (!user) {
        redirect(302, '/login?next=' + url.pathname);
    }

    const { data, error: surrealError } = await surrealQuery('SELECT * FROM pages:i1csv7cevkek4f9ikbyc');

    if (surrealError) {
        error(400, surrealError);
    }

    return {
        about: data[0].result[0]
    };

}) satisfies PageServerLoad;