const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'https://awwclgfojcppadbujabt.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF3d2NsZ2ZvamNwcGFkYnVqYWJ0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg0Nzc2OTQsImV4cCI6MjA4NDA1MzY5NH0.P8B4CW2qQuwO-hksXfLAxEOP51ppBJTuAc20Qz4Etzs';

const supabase = createClient(supabaseUrl, supabaseKey);

async function signup() {
    const { data, error } = await supabase.auth.signUp({
        email: 'subscribe.catalog@gmail.com',
        password: 'Joseluis_49',
    });

    if (error) {
        console.error('Error:', error.message);
    } else {
        console.log('Success! User created:', data.user?.email);
        console.log('Session:', data.session ? 'Active' : 'Needs confirmation');
    }
}

signup();
