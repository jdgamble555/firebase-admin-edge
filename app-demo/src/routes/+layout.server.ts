import { error } from "@sveltejs/kit";
import type { LayoutServerLoad } from "./$types";

export const load = (async ({ locals: { authServer } }) => {

    const { data, error: firebaseError } = await authServer.getUser();

    if (firebaseError) {
        error(400, firebaseError);
    }

    if (!data) {
        return {
            user: null
        };
    }

    return {
        user: data
    };

}) satisfies LayoutServerLoad;