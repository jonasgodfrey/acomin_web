// necessary dependencies
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const axios = require('axios');
require('dotenv').config();
const app = express();
const PORT = 3000;

// Set view engine to EJS
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static('public'));

// Middleware to parse form data
app.use(express.urlencoded({ extended: false }));

// prevent back button access after logout and Disable caching for sensitive routes
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// Secure session setup
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Prevent creating sessions for unauthenticated users
    cookie: {
        httpOnly: true, // Helps prevent XSS attacks
        maxAge: 600000 // 10-minute session expiration
    }
}));

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});


// Middleware to check user authentication to login
function checkAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        return res.redirect('/signin');
    }
}


// Sign-up page
app.get('/signup', (req, res) => {
    res.render('signup');  // sign up page
});

// Handle user sign-up by getting the credential
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    // Hash the password before storing so that it can be safe
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).send('Internal server error');
        }

        // Insert user into MySQL
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting user into database:', err);
                return res.status(500).send('Sign-up error');
            }
            res.redirect('/signin');
        });
    });
});

// GET: Sign-in page
app.get('/signin', (req, res) => {
    res.render('signin');
});

// POST: Handle user sign-in
app.post('/signin', (req, res) => {
    const { email, password } = req.body;

    // Check if the user exists in the database by email
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Internal server error');
        }

        if (results.length === 0) {
            return res.status(401).send('No user found with that email');
        }

        const user = results[0];

        // Compare the hashed password with the entered password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).send('Internal server error');
            }

            if (isMatch) {
                req.session.userId = user.id;
                req.session.username = user.username;
                console.log("User logged in successfully");

                // Redirect to the data page after successful login
                res.redirect('/display-data'); // Redirect to display data
            } else {
                res.status(401).send('Incorrect password');
            }
        });
    });
});

// GET: Logout
// Handle user logout securely
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/signin'); // logout and come back to the login page
    });
});

function checkAuth(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.redirect('/signin');
    }
}


// A route to fetch and store data from API
app.get('/fetch-data', async (req, res) => {
    try {
        // Fetch data from the API
        const url =  process.env.MSV_API;
        const response = await axios.get(url);
        const data = response.data;  // Extract the data from the response
        console.log('Fetched data:', data); // Log the fetched data

        // Prepare an array of promises for all insert operations
        const insertPromises = data.map((item) => {
            return new Promise((resolve, reject) => {
                // Check if record already exists
                const checkQuery = 'SELECT * FROM MSVTable WHERE id = ?';
                db.query(checkQuery, [item._id], (err, results) => {
                    if (err) {
                        console.error('Error checking for existing record:', err);
                        return reject(err);
                    }

                    if (results.length > 0) {
                        // Record exists, skip insertion
                        console.log('Record already exists for ID:', item._id);
                        return resolve();
                    } else {
                        // Insert new record
                        const insertQuery = `
                        INSERT INTO MSVTable (
                            id, 
                            formhub_uuid, 
                            start_time, 
                            end_time, 
                            msvModule, 
                            state, 
                            lga, 
                            Monitor_Name, 
                            Monitor_Designation, 
                            Reporting_Period, 
                            Reporting_Year, 
                            Visit_Date, 
                            cboNameVisited, 
                            ward, 
                            community,
                             HF, 
                            cbo_rating, 
                            documentation_of_activities, 
                            participation_trad_leader, 
                            participation_religious_leader,
                             participation_political_leader, 
                            participation_private_sector,
                             issues_affecting_quality, 
                            community_participation_adv_visit, 
                            success_story_achieved, 
                            success_stories_list, 
                            cost_of_success_story, 
                            cat_member_challenges, 
                            list_of_cat_member_challenges, 
                            spo_visit_count, 
                            satisfied_with_supervision, 
                            org_requires_more_support, 
                            version, 
                            meta_instanceID, 
                            xform_id_string, 
                            uuid, 
                            status, 
                            geolocation, 
                            submission_time, 
                            submitted_by
                        ) VALUES (?)`;

                        const values = [[
                            item._id,
                            item['formhub/uuid'],
                            item.start,
                            item.end,
                            item.msvModule,
                            item.state,
                            item.lga,
                            item.Monitor_Name,
                            item.Monitor_Designation,
                            item.Reporting_Period,
                            item.Reporting_Year,
                            item.Visit_Date,
                            item['CBOOfficeVisitModule/cboNameVisited'] || null,
                            item['CBOOfficeVisitModule/ward'] || null,
                            item['CBOOfficeVisitModule/Community'] || null,
                            item['CBOOfficeVisitModule/HF'] || null,
                            item['CBOOfficeVisitModule/CBOimplenetationRating'] || null,
                            item['CBOOfficeVisitModule/How_is_the_documentation_of_your_activities_done_on_the_project'] || null,
                            item['CBOOfficeVisitModule/LevelOfParticipationTradLeader'] || null,
                            item['CBOOfficeVisitModule/LevelOfParticipationReligiousLeader'] || null,
                            item['CBOOfficeVisitModule/LevelOfParticipationPoliticalLeader'] || null,
                            item['CBOOfficeVisitModule/LevelOfParticipationPrivateSector'] || null,
                            item['CBOOfficeVisitModule/IssuesAffectngQualityOfMalSevice'] || null,
                            item['CBOOfficeVisitModule/LevelOfCommunityParticipationonAdvVisit'] || null,
                            item['CBOOfficeVisitModule/DidYouAchieveSuccessStory'] || null,
                            item['CBOOfficeVisitModule/ListOfSuccessStories'] || null,
                            item['CBOOfficeVisitModule/CostOfSuccessStory'] || null,
                            item['CBOOfficeVisitModule/AnyCATMemberChallenges'] || null,
                            item['CBOOfficeVisitModule/ListCATMemberChallenges'] || null,
                            item['CBOOfficeVisitModule/NumberOfTimesSPOvisitCBO'] || null,
                            item['CBOOfficeVisitModule/SatisfiedWithLevelOfSupervision'] || null,
                            item['CBOOfficeVisitModule/DoesOrgRequireMoreSupport'] || null,
                            item.__version__,
                            item['meta/instanceID'],
                            item._xform_id_string,
                            item._uuid,
                            item._status,
                            (item._geolocation && item._geolocation.length === 2 && item._geolocation[0] && item._geolocation[1])
                                ? `POINT(${item._geolocation[0]}, ${item._geolocation[1]})`
                                : null,
                            item._submission_time,
                            item._submitted_by || null
                        ]];


                        db.query(insertQuery, values, (err, result) => {
                            if (err) {
                                console.error('Error inserting data:', err);
                                return reject(err);
                            }
                            console.log('Data inserted successfully:', result);
                            resolve(result);
                        });
                    }
                });
            });
        });

        await Promise.all(insertPromises); // Wait for all insertions to complete
        res.status(200).json({ message: 'Data fetched and stored successfully', data });
    } catch (error) {
        console.error('Error fetching data from API:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Error fetching data' });
    }
});


// A route to display data in a table
app.get('/display-data', checkAuth, (req, res) => {
    const query = 'SELECT * FROM MSVTable';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).send('An error occurred while fetching data');
        } else {
            res.render('data', { data: results });
        }
    });
});

app.get('/display-data/:id', checkAuth, (req, res) => {
    const id = req.params.id; // Get ID from request parameters
    const query = 'SELECT * FROM MSVTable WHERE id = ?'; // Make sure to adjust this query if you only need specific fields
    db.query(query, [id], (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).json({ error: 'An error occurred while fetching data.' });
        } else if (results.length === 0) {
            res.status(404).json({ error: 'No data found for the given ID.' });
        } else {
            res.json(results[0]); // Send back the details of the specific record
        }
    });
});


// A route to display charts
app.get('/display-charts', checkAuth, (req, res) => {
    const query = 'SELECT * FROM MSVTable';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).send('An error occurred while fetching data');
        } else {
            res.render('dynamicchart', { chart: results }); // Render the 'dynamicchart.ejs' template
        }
    });
});

// Route to fetch and insert data
app.get('/submission-data', async (req, res) => {
    try {
        const url = process.env.Client_API;
        const response = await axios.get(url);
        const data = response.data;

        // Prepare promises for all insert operations
        const insertPromises = data.map((item) => {
            return new Promise((resolve, reject) => {
                // Check if record already exists
                const checkQuery = 'SELECT * FROM ClientsTable WHERE id = ?';
                db.query(checkQuery, [item._id], (err, results) => {
                    if (err) {
                        console.error('Error checking for existing record:', err);
                        return reject(err);
                    }

                    if (results.length > 0) {
                        // Record exists, skip insertion
                        console.log('Record already exists for ID:', item._id);
                        return resolve();
                    } else {
                        const query = `
                            INSERT INTO ClientsTable (
                                id,
                                formhub_uuid,
                                start_time,
                                end_time,
                                today,
                                consent,
                                service_cat,
                                serv_received,
                                freq_visit,
                                year,
                                qtr,
                                month,
                                state,
                                lga,
                                cbo,
                                cboemail,
                                ward,
                                hf,
                                resp_name,
                                resp_cat,
                                resp_edu,
                                store_gps,
                                __version__,
                                meta_instanceID,
                                xform_id_string,
                                uuid,
                                status,
                                submission_time,
                                submitted_by,
                                geolocation,
                                hiv_info,
                                infohiv_source,
                                hiv_prev,
                                kindofserv,
                                hivduration,
                                hivattitude,
                                hivgender_hw,
                                hivmed_given,
                                hivdrug_side,
                                hivdescrimination,
                                hivassess_quality,

                                 attitude,
                                 mal_info,
                                 info_source,
                                 prev_how,
                                 given_med,
                                 side_effect,
                                 access_hf,
                                 attended_by_hf,
                                 offer_anc,
                                 receive_ipt,
                                 free_mal_aware,
                                 payto_receive,
                                 tested,
                                 result_tested,                          
                                 
                                 tb_info,
                                 tb_source,
                                 prev_tb,
                                 tbdrug_given,
                                 drug_sideeffect,
                                 tbsideeffect_exp,
                                 tbaccess_hf,
                                 tbhw,
                                 tbanc,
                                 freetbaware,
                                 tbservdeny,
                                 kindtbserv,
                                 paytbserv,
                                 tbduration,
                                 tbattitude,
                                 child_name,
                                 assess_quality,
                                 tbassess_quality

    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ST_GeomFromText(?),?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?,?,?,?,?,?,?,?,?)`;
                                     

                        
                        const values = [
                            item._id,
                            item['formhub/uuid'],
                            item.start ? item.start.replace('Z', '') : null,
                            item.end ? item.end.replace('Z', '') : null,
                            item.today ? item.today.replace('Z', '') : null,
                            item['group_oc0ad90/consent'],
                            item['group_oc0ad95/service_cat'],
                            item['group_oc0ad95/serv_received'],
                            item['group_oc0ad95/freq_visit'],
                            item['group_oc0ad95/year'],
                            item['group_oc0ad95/qtr'],
                            item['group_oc0ad95/month'],
                            item['group_oc0ad95/state'],
                            item['group_oc0ad95/lga'],
                            item['group_oc0ad95/cbo'],
                            item['group_oc0ad95/cboemail'],
                            item['group_oc0ad95/ward'],
                            item['group_oc0ad95/hf'],
                            item['group_oc0ad95/resp_name'],
                            item['group_oc0ad95/resp_cat'],
                            item['group_oc0ad95/resp_edu'],
                            item.store_gps,
                            item.__version__,
                            item['meta/instanceID'],
                            item._xform_id_string,
                            item._uuid,
                            item._status,
                            item._submission_time,
                            item._submitted_by || null,
                            (item._geolocation && item._geolocation.length === 2 && item._geolocation[0] && item._geolocation[1])
                                ? `POINT(${item._geolocation[0]} ${item._geolocation[1]})`
                                : null,
                                item[ 'group_oc0ad92/hiv_info'],
                                item['group_oc0ad92/infohiv_source'],
                                item['group_oc0ad92/hiv_prev'] ,
                                item['group_oc0ad92/kindofserv'] ,
                                item['group_oc0ad92/hivduration'],
                                item['group_oc0ad92/hivattitude'],
                                item['group_oc0ad92/hivgender_hw'],
                                item['group_oc0ad92/hivmed_given'],
                                item['group_oc0ad92/hivdrug_side'],
                                item['group_oc0ad92/hivdescrimination'],
                                item['group_oc0ad92/hivassess_quality'],


                                item['group_oc0ad91/attitude'] || null,
                                item['group_oc0ad91/mal_info'] || null,
                                item['group_oc0ad91/info_source'] || null,
                                item['group_oc0ad91/prev_how'] || null,
                                item['group_oc0ad91/given_med'] || null,
                                item['group_oc0ad91/side_effect'] || null,
                                item['group_oc0ad91/access_hf'] || null,
                                item['group_oc0ad91/attended_by_hf'] || null,
                                item['group_oc0ad91/offer_anc'] || null,
                                item['group_oc0ad91/receive_ipt'] || null,
                                item['group_oc0ad91/free_mal_aware'] || null,
                                item['group_oc0ad91/payto_receive'] || null,
                                item['group_oc0ad91/tested'] || null,
                                item['group_oc0ad91/result_tested'] || null,
                                
                                item['group_oc0ad93/tb_info'] || null,
                                item['group_oc0ad93/tb_source'] || null,
                                item['group_oc0ad93/prev_tb'] || null,
                                item['group_oc0ad93/tbdrug_given'] || null,
                                item['group_oc0ad93/drug_sideeffect'] || null,
                                item['group_oc0ad93/tbsideeffect_exp'] || null,
                                item['group_oc0ad93/tbaccess_hf'] || null,
                                item['group_oc0ad93/tbhw'] || null,
                                item['group_oc0ad93/tbanc'] || null,
                                item['group_oc0ad93/freetbaware'] || null,
                                item['group_oc0ad93/tbservdeny'] || null,
                                item['group_oc0ad93/kindtbserv'] || null,
                                item['group_oc0ad93/paytbserv'] || null,
                                item['group_oc0ad93/tbduration'] || null,
                                item['group_oc0ad93/tbattitude'] || null,
                                item['group_oc0ad95/child_name'] || null,
                                item['group_oc0ad91/assess_quality'],
                                item['group_oc0ad93/tbassess_quality']
                        ];
                        
                        db.query(query, values, (err, result) => {
                            if (err) {
                                console.error('Error inserting data:', err);
                                return reject(err);
                            }
                            console.log('Data inserted successfully:', result);
                            resolve(result);
                        });
                    }
                });
            });
        });

        await Promise.all(insertPromises); // Wait for all insertions to complete
        res.status(200).json({ message: 'Data fetched and stored successfully', data });
    } catch (error) {
        console.error('Error fetching data from API:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Route to display data in a table
app.get('/submission-table', (req, res) => {
    const query = 'SELECT * FROM ClientsTable ORDER BY qtr DESC';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).send('An error occurred while fetching data');
        } else {
            res.render('submission', { data: results });
        }
    });
});

app.get('/submission-table/:id', (req, res) => {
    const id = req.params.id; // Get ID from request parameters
    const query = 'SELECT * FROM ClientsTable WHERE id = ?'; // Ensure the query uses the correct column
    db.query(query, [id], (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            return res.status(500).json({ error: 'An error occurred while fetching data.' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'No data found for the given ID.' });
        }
        res.json(results[0]); // Send back the details of the specific record
    });
});



// Route to display charts
app.get('/submission-charts', (req, res) => {
    const query = 'SELECT * FROM ClientsTable';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).send('An error occurred while fetching data');
        } else {
            res.render('dynamicchart', { chart: results });
        }
    });
});

app.get('/attendance-data', async (req, res) => {
    try {
        const url =process.env.Attendance_API ;
        const response = await axios.get(url);
        const data = response.data;  // Extract the data from the response

        console.log('Fetched data:', data); // Log the fetched data

        // Prepare an array of promises for all insert operations
        const insertPromises = data.map((item) => {
            return new Promise((resolve, reject) => {
                // Check for duplicate entry by ID
                const queryCheck = `SELECT COUNT(*) as count FROM attendance_records WHERE id = ?`;
                const valuesCheck = [item._id];

                db.query(queryCheck, valuesCheck, (err, result) => {
                    if (err) {
                        console.error('Error checking for duplicate:', err);
                        return reject(err);
                    }

                    // Ensure result is defined and check for duplicates
                    if (result && result[0] && result[0].count > 0) {
                        return resolve(true); // Skip this entry
                    }

                    // Prepare the insert query only if attendance data is available
                    if (item["eAtt/attendance"] && item["eAtt/attendance"].length > 0) {
                        const attendanceItem = item["eAtt/attendance"][0]; // Get the first attendance item

                        const query = `
                            INSERT INTO attendance_records (
                                id, 
                                formhub_uuid,
                                eAtt_level,
                                eAtt_venue,
                                eAtt_name_activity,
                                eAtt_state_list,
                                eAtt_name_of_filler,
                                meeting_venue,
                                name_of_person_filling_attendance,
                                date_of_activity,
                                name_activity,
                                participant_name,
                                participant_org,
                                sex,
                                Designation,
                                email_address,
                                state
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `;

                        const values = [
                            item._id,
                            item["formhub/uuid"],
                            item["eAtt/Level"],
                            item["eAtt/Venue"],
                            item["eAtt/NameActivityy"],
                            item["eAtt/statelist"],
                            item["eAtt/NameOfFiller"],
                            attendanceItem["eAtt/attendance/MeetingVenue"],
                            attendanceItem["eAtt/attendance/NameOfPersonFillingAttendance"],
                            attendanceItem["eAtt/attendance/DateOfActivity"],
                            attendanceItem["eAtt/attendance/NameActivity"],
                            attendanceItem["eAtt/attendance/ParticipantName"],
                            attendanceItem["eAtt/attendance/ParticipantOrg"],
                            attendanceItem["eAtt/attendance/sex"],
                            attendanceItem["eAtt/attendance/Designation"], 
                            attendanceItem["eAtt/attendance/EmailAdd"],
                            attendanceItem["eAtt/attendance/state"]
                        ];

                        // Insert data into the database
                        db.query(query, values, (err, result) => {
                            if (err) {
                                console.error('Error inserting data:', err);
                                return reject(err);
                            }
                            console.log('Data inserted successfully:', result);
                            resolve(true); // Resolve once the data is inserted
                        });
                    } else {
                        return resolve(true); // Skip if no attendance data
                    }
                });
            });
        });
        await Promise.all(insertPromises); // Wait for all insertions to complete

        res.status(200).json({ message: 'Data fetched and stored successfully', data: finalData });
    } catch (error) {
        console.error('Error fetching data from API:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Error fetching data' });
    }
});

app.get('/attendance-table', (req, res) => {
    const query = 'SELECT * FROM attendance_records';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching data:', error);
            res.status(500).send('An error occurred while fetching data');
        } else {
            res.render('attendance', { data: results }); // Render the 'data.ejs' file
        }
    });
});
// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
