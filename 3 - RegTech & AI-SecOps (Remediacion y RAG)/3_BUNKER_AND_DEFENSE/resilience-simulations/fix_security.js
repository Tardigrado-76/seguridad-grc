import sql from './db.js'

async function fixSecurity() {
    console.log('--- Applying Professional Security Fixes ---')

    try {
        // 1. Recreate handle_new_user with SECURITY DEFINER and FIXED search_path
        // This prevents "search_path hijacking" vulnerabilities.
        console.log('Securing handle_new_user function...')
        await sql`
      CREATE OR REPLACE FUNCTION public.handle_new_user()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = public, pg_catalog -- IMPACTANTE: Fija el search_path para evitar mutabilidad insegura
      AS $$
      BEGIN
        INSERT INTO public.profiles (id, email, full_name)
        VALUES (new.id, new.email, new.raw_user_meta_data->>'full_name');
        RETURN new;
      END;
      $$;
    `

        // 2. Best Practice: Revoke execute permission from Public
        // Since this is a trigger function invoked by the database event, 
        // it doesn't need to be exposed to the public API or called directly by users.
        console.log('Revoking unnecessary public execution rights...')
        await sql`REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC;`

        console.log('✅ Security vulnerabilities resolved.')

    } catch (e) {
        console.error('❌ Error applying security fixes:', e)
    } finally {
        await sql.end()
    }
}

fixSecurity()
